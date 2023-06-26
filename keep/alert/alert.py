import enum
import logging
import typing

from pydantic.dataclasses import dataclass

from keep.contextmanager.contextmanager import ContextManager
from keep.iohandler.iohandler import IOHandler
from keep.step.step import Step, StepError


class AlertStatus(enum.Enum):
    RESOLVED = "resolved"
    FIRING = "firing"


@dataclass
class Alert:
    alert_id: str
    alert_source: str
    alert_owners: typing.List[str]
    alert_tags: typing.List[str]
    alert_interval: int
    alert_steps: typing.List[Step]
    alert_actions: typing.List[Step]
    alert_file: str = None
    on_failure: Step = None

    def __post_init__(self):
        self.logger = logging.getLogger(__name__)
        self.alert_file = self.alert_source.split("/")[-1]
        self.io_nandler = IOHandler()
        self.context_manager = ContextManager.get_instance()

    def _get_alert_context(self):
        return {
            "alert_id": self.alert_id,
            "alert_owners": self.alert_owners,
            "alert_tags": self.alert_tags,
            "alert_steps_context": self.context_manager.steps_context,
            "alert_actions_context": self.context_manager.actions_context,
        }

    def run_step(self, step: Step):
        self.logger.info("Running step %s", step.step_id)
        if step.foreach:
            rendered_foreach = self.io_nandler.render(step.foreach)
            for f in rendered_foreach:
                self.logger.debug("Step is a foreach step")
                self.context_manager.set_for_each_context(f)
                step_output = step.run()
                self.context_manager.set_step_context(
                    step.step_id, results=step_output, foreach=True
                )
        else:
            step_output = step.run()
            self.context_manager.set_step_context(step.step_id, results=step_output)
        self.logger.info("Step %s ran successfully", step.step_id)
        return step_output

    def run_steps(self):
        self.logger.debug(f"Running steps for alert {self.alert_id}")
        for step in self.alert_steps:
            try:
                self.run_step(step)
            except StepError as e:
                self.logger.error(f"Step {step.step_id} failed: {e}")
                raise
        self.logger.debug(f"Steps for alert {self.alert_id} ran successfully")

    def run_action(self, action: Step):
        self.logger.info("Running action %s", action.name)
        try:
            action_status = action.run()
            action_error = None
            self.logger.info("Action %s ran successfully", action.name)
        except Exception as e:
            self.logger.error(f"Action {action.name} failed: {e}")
            action_status = False
            action_error = str(e)
        return action_status, action_error

    def run_actions(self):
        self.logger.debug("Running actions")
        actions_firing = []
        actions_errors = []
        for action in self.alert_actions:
            action_status, action_error = self.run_action(action)
            actions_firing.append(action_status)
            actions_errors.append(action_error)
        self.logger.debug("Actions run")
        return actions_firing, actions_errors

    def run(self):
        self.logger.debug(f"Running alert {self.alert_id}")
        # todo: check why is this needed?
        self.context_manager.set_alert_context(self._get_alert_context())
        self.run_steps()
        actions_firing, actions_errors = self.run_actions()

        # Save the state
        #   alert is firing if one its actions is firing
        alert_status = (
            AlertStatus.FIRING.value
            if any(actions_firing)
            else AlertStatus.RESOLVED.value
        )
        self.context_manager.set_last_alert_run(
            alert_id=self.alert_id,
            alert_context=self._get_alert_context(),
            alert_status=alert_status,
        )
        self.logger.debug(f"Finish to run alert {self.alert_id}")
        return actions_errors

    def _handle_actions(self):
        self.logger.debug(f"Handling actions for alert {self.alert_id}")
        for action in self.alert_actions:
            action.run()
        self.logger.debug(f"Actions handled for alert {self.alert_id}")

    def run_missing_steps(self, end_step=None):
        """Runs steps without context (when the alert is run by the API)"""
        self.logger.debug(f"Running missing steps for alert {self.alert_id}")
        steps_context = self.context_manager.get_full_context().get("steps")
        for step in self.alert_steps:
            # if we reached the end step, stop
            if end_step and step.step_id == end_step.step_id:
                break
            # If we don't have context for the step, run it
            if step.step_id not in steps_context:
                try:
                    self.run_step(step)
                except StepError as e:
                    self.logger.error(f"Step {step.step_id} failed: {e}")
                    raise
        self.logger.debug(f"Missing steps for alert {self.alert_id} ran successfully")
