import hashlib
import itertools
import json
import logging

import celpy
import chevron

from keep.api.core.db import assign_alert_to_group as assign_alert_to_group_db
from keep.api.core.db import create_alert as create_alert_db
from keep.api.core.db import get_rules as get_rules_db
from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.api.models.group import GroupDto


class RulesEngine:
    def __init__(self, tenant_id=None):
        self.tenant_id = tenant_id
        self.logger = logging.getLogger(__name__)

    def _calc_max_severity(self, severities):
        if not severities:
            self.logger.info(
                "Could not calculate max severity from empty list - fallbacking to info"
            )
            return str(AlertSeverity.INFO)

        severities = [AlertSeverity(severity) for severity in severities]
        max_severity = max(severities, key=lambda severity: severity.order)
        return str(max_severity)

    def run_rules(self, events: list[AlertDto]):
        self.logger.info("Running rules")
        rules = get_rules_db(tenant_id=self.tenant_id)

        groups = []
        for rule in rules:
            self.logger.info(f"Evaluating rule {rule.name}")
            for event in events:
                self.logger.info(
                    f"Checking if rule {rule.name} apply to event {event.id}"
                )
                try:
                    rule_result = self._check_if_rule_apply(rule, event)
                except Exception:
                    self.logger.exception(
                        f"Failed to evaluate rule {rule.name} on event {event.id}"
                    )
                    continue
                if rule_result:
                    self.logger.info(
                        f"Rule {rule.name} on event {event.id} is relevant"
                    )
                    group_fingerprint = self._calc_group_fingerprint(event, rule)
                    # Add relation between this event and the group
                    updated_group = assign_alert_to_group_db(
                        tenant_id=self.tenant_id,
                        alert_id=event.event_id,
                        rule_id=str(rule.id),
                        group_fingerprint=group_fingerprint,
                    )
                    groups.append(updated_group)
                else:
                    self.logger.info(
                        f"Rule {rule.name} on event {event.id} is not relevant"
                    )
        self.logger.info("Rules ran successfully")
        # if we don't have any updated groups, we don't need to create any alerts
        if not groups:
            return
        # get the rules of the groups
        updated_group_rule_ids = [group.rule_id for group in groups]
        updated_rules = get_rules_db(
            tenant_id=self.tenant_id, ids=updated_group_rule_ids
        )
        # more convenient to work with a dict
        updated_rules_dict = {str(rule.id): rule for rule in updated_rules}
        # Now let's create a new alert for each group
        grouped_alerts = []
        for group in groups:
            rule = updated_rules_dict.get(group.rule_id)
            group_fingerprint = hashlib.sha256(
                "|".join([str(group.id), group.group_fingerprint]).encode()
            ).hexdigest()
            group_attributes = GroupDto.get_group_attributes(group.alerts)
            context = {
                "group": group_attributes,
                # Shahar: first, group have at least one alert.
                #         second, the only supported {{ }} are the ones in the group
                #          attributes, so we can use the first alert because they are the same for any other alert in the group
                **group.alerts[0].event,
            }
            group_description = chevron.render(rule.group_description, context)
            group_severity = self._calc_max_severity(
                [alert.event["severity"] for alert in group.alerts]
            )
            # group all the sources from all the alerts
            group_source = list(
                set(
                    itertools.chain.from_iterable(
                        [alert.event["source"] for alert in group.alerts]
                    )
                )
            )
            # if the group has "group by", add it to the group name
            if rule.grouping_criteria:
                group_name = f"Alert group genereted by rule {rule.name} | group:{group.group_fingerprint}"
            else:
                group_name = f"Alert group genereted by rule {rule.name}"

            # create the alert
            group_alert = create_alert_db(
                tenant_id=self.tenant_id,
                provider_type="group",
                provider_id=rule.id,
                # todo: event should support list?
                event={
                    "name": group_name,
                    "id": group_fingerprint,
                    "description": group_description,
                    "lastReceived": group_attributes.get("last_update_time"),
                    "severity": group_severity,
                    "source": group_source,
                    # TODO: status should be calculated from the alerts
                    "status": AlertStatus.FIRING.value,
                    "pushed": True,
                    **group_attributes,
                },
                fingerprint=group_fingerprint,
            )
            grouped_alerts.append(group_alert)
            self.logger.info(f"Created alert {group_alert.id} for group {group.id}")
        self.logger.info(f"Rules ran, {len(grouped_alerts)} alerts created")
        alerts_dto = [AlertDto(**alert.event) for alert in grouped_alerts]
        return alerts_dto

    def _extract_subrules(self, expression):
        # CEL rules looks like '(source == "sentry") && (source == "grafana" && severity == "critical")'
        # and we need to extract the subrules
        sub_rules = expression.split(") && (")
        # the first and the last rules will have a ( or ) at the beginning or the end
        # e.g. for the example of:
        #           (source == "sentry") && (source == "grafana" && severity == "critical")
        # than sub_rules[0] will be (source == "sentry" and sub_rules[-1] will be source == "grafana" && severity == "critical")
        # so we need to remove the first and last character
        sub_rules[0] = sub_rules[0][1:]
        sub_rules[-1] = sub_rules[-1][:-1]
        return sub_rules

    # TODO: a lot of unit tests to write here
    def _check_if_rule_apply(self, rule, event: AlertDto):
        sub_rules = self._extract_subrules(rule.definition_cel)
        payload = event.dict()
        # workaround since source is a list
        # todo: fix this in the future
        payload["source"] = payload["source"][0]

        # what we do here is to compile the CEL rule and evaluate it
        #   https://github.com/cloud-custodian/cel-python
        #   https://github.com/google/cel-spec
        env = celpy.Environment()
        for sub_rule in sub_rules:
            ast = env.compile(sub_rule)
            prgm = env.program(ast)
            activation = celpy.json_to_cel(json.loads(json.dumps(payload, default=str)))
            r = prgm.evaluate(activation)
            if r:
                return True
        # no subrules matched
        return False

    def _calc_group_fingerprint(self, event: AlertDto, rule):
        # extract all the grouping criteria from the event
        # e.g. if the grouping criteria is ["event.labels.queue", "event.labels.cluster"]
        #     and the event is:
        #    {
        #      "labels": {
        #        "queue": "queue1",
        #        "cluster": "cluster1",
        #        "foo": "bar"
        #      }
        #    }
        # than the group_fingerprint will be "queue1,cluster1"
        event_payload = event.dict()
        grouping_criteria = rule.grouping_criteria
        group_fingerprint = []
        for criteria in grouping_criteria:
            # we need to extract the value from the event
            # e.g. if the criteria is "event.labels.queue"
            # than we need to extract the value of event["labels"]["queue"]
            criteria_parts = criteria.split(".")
            value = event_payload
            for part in criteria_parts:
                value = value.get(part)
            group_fingerprint.append(value)
        # if, for example, the event should have labels.X but it doesn't,
        # than we will have None in the group_fingerprint
        if not group_fingerprint:
            self.logger.warning(
                f"Failed to calculate group fingerprint for event {event.id} and rule {rule.name}"
            )
            return "none"
        return ",".join(group_fingerprint)
