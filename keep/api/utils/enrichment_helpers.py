from keep.api.models.alert import AlertDto


def parse_and_enrich_deleted_and_assignees(alert: AlertDto, enrichments: dict):
    # tb: we'll need to refactor this at some point since its flaky
    # assignees and deleted are special cases that we need to handle
    # they are kept as a list of timestamps and we need to check if the
    # timestamp of the alert is in the list, if it is, it means that the
    # alert at that specific time was deleted or assigned.
    #
    # THIS IS MAINLY BECAUSE WE ALSO HAVE THE PULLED ALERTS,
    # OTHERWISE, WE COULD'VE JUST UPDATE THE ALERT IN THE DB
    deleted_last_received = enrichments.pop("deletedAt", [])
    if alert.lastReceived in deleted_last_received:
        alert.deleted = True
    assignees: dict = enrichments.pop("assignees", {})
    assignee = assignees.get(alert.lastReceived)
    if assignee:
        alert.assignee = assignee
