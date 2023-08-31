import { load, JSON_SCHEMA } from "js-yaml";
import { Provider } from "../providers/providers";
import {
  BranchedStep,
  Definition,
  SequentialStep,
  Step,
  StepDefinition,
  Uid,
} from "sequential-workflow-designer";
import { KeepStep } from "./types";
import { Action, Alert } from "./alert";

export function getToolboxConfiguration(providers: Provider[]) {
  /**
   * Generates the toolbox items
   */
  const [steps, actions] = providers.reduce(
    ([steps, actions], provider) => {
      const step = {
        componentType: "task",
        properties: {
          stepParams: provider.query_params!,
          actionParams: provider.notify_params!,
        },
      };
      if (provider.can_query)
        steps.push({
          ...step,
          type: `step-${provider.type}`,
          name: `${provider.type}-step`,
        });
      if (provider.can_notify)
        actions.push({
          ...step,
          type: `action-${provider.type}`,
          name: `${provider.type}-action`,
        });
      return [steps, actions];
    },
    [[] as StepDefinition[], [] as StepDefinition[]]
  );
  return {
    groups: [
      {
        name: "Steps",
        steps: steps,
      },
      {
        name: "Actions",
        steps: actions,
      },
      {
        name: "Misc",
        steps: [
          {
            type: "foreach",
            componentType: "container",
            name: "Foreach",
            properties: {},
            sequence: [],
          },
        ],
      },
      // TODO: get conditions from API
      {
        name: "Conditions",
        steps: [
          {
            type: "condition-threshold",
            componentType: "switch",
            name: "Threshold",
            properties: {
              value: "",
              compare_to: "",
            },
            branches: {
              true: [],
              false: [],
            },
          },
          {
            type: "condition-assert",
            componentType: "switch",
            name: "Assert",
            properties: {
              value: "",
              compare_to: "",
            },
            branches: {
              true: [],
              false: [],
            },
          },
        ],
      },
    ],
  };
}

export function getActionOrStepObj(
  actionOrStep: any,
  type: "action" | "step"
): KeepStep {
  /**
   * Generate a step or action definition (both are kinda the same)
   */
  return {
    id: Uid.next(),
    name: actionOrStep.name,
    componentType: "task",
    type: `${type}-${actionOrStep.provider?.type}`,
    properties: {
      config: actionOrStep.provider?.config,
      with: actionOrStep.provider?.with,
    },
  };
}

export function generateCondition(condition: any, action: any): any {
  const generatedCondition = {
    id: Uid.next(),
    name: condition.name,
    type: `condition-${condition.type}`,
    componentType: "switch",
    alias: condition.alias,
    // TODO: this needs to be handled better
    properties: {
      value: condition.value,
      compare_to: condition.compare_to,
      assert: condition.assert,
    },
    branches: {
      true: [getActionOrStepObj(action, "action")],
      false: [],
    },
  };

  // If this is a foreach, we need to add the foreach to the condition
  if (action.foreach) {
    return {
      id: Uid.next(),
      type: "foreach",
      componentType: "container",
      name: "Foreach",
      properties: {
        value: action.foreach,
      },
      sequence: [generatedCondition],
    };
  }

  return generatedCondition;
}

export function generateWorkflow(
  workflowId: string,
  description: string,
  steps: Step[],
  conditions: Step[],
  triggers: { [key: string]: string } = {}
): Definition {
  /**
   * Generate the workflow definition
   */
  const alert = {
    id: Uid.next(),
    name: "Workflow",
    componentType: "container",
    type: "alert",
    properties: {
      id: workflowId,
      description: description,
      isLocked: true,
      ...triggers,
    },
    sequence: [...steps, ...conditions],
  };
  return { sequence: [alert], properties: {} };
}

export function parseWorkflow(workflowString: string): Definition {
  /**
   * Parse the alert file and generate the definition
   */
  const parsedWorkflowFile = load(workflowString, {
    schema: JSON_SCHEMA,
  }) as any;
  // This is to support both old and new structure of workflow
  const workflow = parsedWorkflowFile.alert
    ? parsedWorkflowFile.alert
    : parsedWorkflowFile.workflow;
  const steps =
    workflow.steps?.map((step: any) => {
      return getActionOrStepObj(step, "step");
    }) || [];
  const conditions = [] as any;
  workflow.actions?.forEach((action: any) => {
    // This means this action always runs, there's no condition and no alias
    if (!action.condition && !action.if) {
      steps.push(getActionOrStepObj(action, "action"));
    }
    // If this is an alias, we need to find the existing condition and add this action to it
    else if (action.if) {
      const cleanIf = action.if.replace("{{", "").replace("}}", "").trim();
      const existingCondition = conditions.find(
        (a: any) => a.alias === cleanIf
      );
      existingCondition?.branches.true.push(
        getActionOrStepObj(action, "action")
      );
    } else {
      action.condition.forEach((condition: any) => {
        conditions.push(generateCondition(condition, action));
      });
    }
  });

  const triggers =
    workflow.triggers?.reduce((prev: any, curr: any) => {
      const currType = curr.type;
      let value = curr.value;
      if (currType === "alert") {
        value = curr.filters.find((f: any) => f.key === "source").value;
      } else if (currType === "manual") {
        value = "true";
      }
      prev[currType] = value;
      return prev;
    }, {}) || {};

  return generateWorkflow(
    workflow.id,
    workflow.description,
    steps,
    conditions,
    triggers
  );
}

function getActionsFromCondition(
  condition: BranchedStep,
  foreach?: string
): Action[] {
  const compiledCondition = {
    name: condition.name,
    type: condition.type.replace("condition-", ""),
    ...condition.properties,
  };
  const compiledActions = condition.branches.true.map((a) => {
    const compiledAction = {
      name: a.name,
      provider: {
        type: a.type.replace("action-", ""),
        config: a.properties.config,
        with: a.properties.with,
      },
      condition: compiledCondition,
    } as Action;
    if (foreach) compiledAction["foreach"] = foreach;
    return compiledAction;
  });
  return compiledActions;
}

export function downloadFileFromString(data: string, filename: string) {
  /**
   * Generated with ChatGPT
   */
  var blob = new Blob([data], { type: "text/plain" });
  var url = URL.createObjectURL(blob);

  var link = document.createElement("a");
  link.href = url;
  link.download = filename;

  link.click();

  URL.revokeObjectURL(url);
}

export function buildAlert(definition: Definition): Alert {
  const alert = definition.sequence[0] as SequentialStep;
  const alertId = (alert.properties.id as string) ?? alert.name;
  const description = (alert.properties.description as string) ?? "";
  const owners = (alert.properties.owners as string[]) ?? [];
  const services = (alert.properties.services as string[]) ?? [];
  // Steps (move to func?)
  const steps = alert.sequence
    .filter((s) => s.type.startsWith("step-"))
    .map((s) => {
      const provider = {
        type: s.type.replace("step-", ""),
        config: s.properties.config as string,
        with:
          (s.properties.with as {
            [key: string]: string | number | boolean | object;
          }) ?? {},
      };
      return {
        name: s.name,
        provider: provider,
      };
    });
  // Actions
  let actions = alert.sequence
    .filter((s) => s.type.startsWith("action-"))
    .map((s) => {
      const provider = {
        type: s.type.replace("action-", ""),
        config: s.properties.config as string,
        with:
          (s.properties.with as {
            [key: string]: string | number | boolean | object;
          }) ?? {},
      };
      return {
        name: s.name,
        provider: provider,
      };
    });
  // Actions > Foreach
  alert.sequence
    .filter((step) => step.type === "foreach")
    ?.forEach((forEach) => {
      const forEachValue = forEach.properties.value as string;
      const condition = (forEach as SequentialStep).sequence.find((c) =>
        c.type.startsWith("condition-")
      ) as BranchedStep;
      const foreachActions = getActionsFromCondition(condition, forEachValue);
      actions = [...actions, ...foreachActions];
    });
  // Actions > Condition
  alert.sequence
    .filter((step) => step.type.startsWith("condition-"))
    ?.forEach((condition) => {
      const conditionActions = getActionsFromCondition(
        condition as BranchedStep
      );
      actions = [...actions, ...conditionActions];
    });

  const triggers = [];
  if (alert.properties.manual === "true") triggers.push({ type: "manual" });
  if (alert.properties.alert) {
    triggers.push({
      type: "alert",
      filters: [{ key: "source", value: alert.properties.alert }],
    });
  }
  if (alert.properties.interval) {
    triggers.push({
      type: "interval",
      value: alert.properties.interval,
    });
  }
  const compiledAlert = {
    id: alertId,
    triggers: triggers,
    description: description,
    owners: owners,
    services: services,
    steps: steps,
    actions: actions,
  };
  return compiledAlert;
}
