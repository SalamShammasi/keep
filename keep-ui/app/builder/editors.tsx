import {
  Title,
  Text,
  TextInput,
  Select,
  SelectItem,
  Subtitle,
  Icon,
} from "@tremor/react";
import { KeyIcon } from "@heroicons/react/20/solid";
import { Properties } from "sequential-workflow-designer";
import {
  useStepEditor,
  useGlobalEditor,
} from "sequential-workflow-designer-react";
import { Provider } from "app/providers/providers";

function EditorLayout({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-col m-2.5">{children}</div>;
}

export function GlobalEditor() {
  const { properties, setProperty } = useGlobalEditor();
  return (
    <EditorLayout>
      <Title>Keep Workflow Editor</Title>
      <Text>
        Use this visual workflow editor to easily create or edit existing Keep
        alerts YAML specification.
      </Text>
      <Text className="mt-5">
        Use the toolbox to add steps, conditions and actions to your workflow
        and click the `Generate` button to compile the alert.
      </Text>
    </EditorLayout>
  );
}

interface keepEditorProps {
  properties: Properties;
  updateProperty: (key: string, value: any) => void;
  installedProviders?: Provider[] | null | undefined;
  providerType?: string;
}

function KeepStepEditor({
  properties,
  updateProperty,
  installedProviders,
  providerType,
}: keepEditorProps) {
  const stepParams = (properties.stepParams ??
    properties.actionParams ??
    []) as string[];
  const existingParams = Object.keys((properties.with as object) ?? {});
  const params = [...stepParams, ...existingParams];
  const uniqueParams = params.filter(
    (item, pos) => params.indexOf(item) === pos
  );

  function propertyChanged(e: any) {
    const currentWith = (properties.with as object) ?? {};
    updateProperty("with", { ...currentWith, [e.target.id]: e.target.value });
  }

  const providerConfig = properties.config as string;
  const installedProviderByTypes = installedProviders?.filter(
    (p) => p.type === providerType
  );

  const DynamicIcon = (props: any) => (
    <svg
      width="24px"
      height="24px"
      viewBox="0 0 24 24"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      {...props}
    >
      {" "}
      <image
        id="image0"
        width={"24"}
        height={"24"}
        href={`/icons/${providerType}-icon.png`}
      />
    </svg>
  );

  return (
    <>
      <Text>Provider Name</Text>
      <Select
        className="my-2.5"
        placeholder={`Select from installed ${providerType} providers`}
        disabled={
          installedProviderByTypes?.length === 0 || !installedProviderByTypes
        }
        onValueChange={(value) => updateProperty("config", value)}
      >
        {
          installedProviderByTypes?.map((provider) => {
            const providerName = provider.details?.name ?? provider.id;
            return (
              <SelectItem
                icon={DynamicIcon}
                key={providerName}
                value={providerName}
              >
                {providerName}
              </SelectItem>
            );
          })!
        }
      </Select>
      <Subtitle>Or</Subtitle>
      <TextInput
        placeholder="Enter provider name manually"
        onChange={(e: any) => updateProperty("config", e.target.value)}
        className="my-2.5"
        value={providerConfig}
      />
      <Text className="my-2.5">Provider Parameters</Text>
      {uniqueParams?.map((key) => {
        let currentPropertyValue = ((properties.with as any) ?? {})[key];
        if (typeof currentPropertyValue === "object") {
          currentPropertyValue = JSON.stringify(currentPropertyValue);
        }
        return (
          <>
            <Text key={key}>{key}</Text>
            <TextInput
              id={`${key}`}
              key={`${key}`}
              placeholder={key}
              onChange={propertyChanged}
              className="mb-2.5"
              value={currentPropertyValue}
            />
          </>
        );
      })}
    </>
  );
}

function KeepThresholdConditionEditor({
  properties,
  updateProperty,
}: keepEditorProps) {
  const currentValueValue = (properties.value as string) ?? "";
  const currentCompareToValue = (properties.compare_to as string) ?? "";
  return (
    <>
      <Text>Value</Text>
      <TextInput
        placeholder="Value"
        onChange={(e: any) => updateProperty("value", e.target.value)}
        className="mb-2.5"
        value={currentValueValue}
      />
      <Text>Compare to</Text>
      <TextInput
        placeholder="Compare with"
        onChange={(e: any) => updateProperty("compare_to", e.target.value)}
        className="mb-2.5"
        value={currentCompareToValue}
      />
    </>
  );
}

function KeepAssertConditionEditor({
  properties,
  updateProperty,
}: keepEditorProps) {
  const currentAssertValue = (properties.assert as string) ?? "";
  return (
    <>
      <Text>Assert</Text>
      <TextInput
        placeholder="E.g. 200 == 200"
        onChange={(e: any) => updateProperty("assert", e.target.value)}
        className="mb-2.5"
        value={currentAssertValue}
      />
    </>
  );
}

function KeepForeachEditor({ properties, updateProperty }: keepEditorProps) {
  const currentValueValue = (properties.value as string) ?? "";

  return (
    <>
      <Text>Foreach Value</Text>
      <TextInput
        placeholder="Value"
        onChange={(e: any) => updateProperty("value", e.target.value)}
        className="mb-2.5"
        value={currentValueValue}
      />
    </>
  );
}

function WorkflowEditor(properties: Properties, updateProperty: any) {
  /**
   * TODO: support generate, add more triggers and complex filters
   *  Need to think about UX for this
   */
  const propertyKeys = Object.keys(properties).filter(
    (k) => k !== "isLocked" && k !== "id"
  );

  return (
    <EditorLayout>
      <Title>Workflow Editor</Title>
      {propertyKeys.map((key) => {
        return (
          <>
            <Text className="capitalize mt-2.5">{key}</Text>
            {key === "manual" ? (
              <div key={key}>
                <input
                  type="checkbox"
                  checked={properties[key] === "true"}
                  onChange={(e) =>
                    updateProperty(key, e.target.checked ? "true" : "false")
                  }
                />
              </div>
            ) : (
              <TextInput
                key={key}
                placeholder="Value"
                onChange={(e: any) => updateProperty(key, e.target.value)}
                value={properties[key] as string}
              />
            )}
          </>
        );
      })}
    </EditorLayout>
  );
}

export default function StepEditor({
  installedProviders,
}: {
  installedProviders?: Provider[] | undefined | null;
}) {
  const { type, componentType, name, setName, properties, setProperty } =
    useStepEditor();

  // Type should be changed to workflow
  if (type === "alert") {
    return WorkflowEditor(properties, setProperty);
  }

  function onNameChanged(e: any) {
    setName(e.target.value);
  }

  const providerType = type.split("-")[1];

  return (
    <EditorLayout>
      <Title className="capitalize">{providerType} Editor</Title>
      <Text>Name</Text>
      <TextInput
        className="mb-2.5"
        icon={KeyIcon}
        value={name}
        onChange={onNameChanged}
      />
      {type.includes("step-") || type.includes("action-") ? (
        <KeepStepEditor
          properties={properties}
          updateProperty={setProperty}
          installedProviders={installedProviders}
          providerType={providerType}
        />
      ) : type === "condition-threshold" ? (
        <KeepThresholdConditionEditor
          properties={properties}
          updateProperty={setProperty}
        />
      ) : type.includes("foreach") ? (
        <KeepForeachEditor
          properties={properties}
          updateProperty={setProperty}
        />
      ) : type === "condition-assert" ? (
        <KeepAssertConditionEditor
          properties={properties}
          updateProperty={setProperty}
        />
      ) : null}
    </EditorLayout>
  );
}
