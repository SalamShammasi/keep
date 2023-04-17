---
sidebar_label: Basic syntax
sidebar_position: 1
---

# Basic Syntax

At Keep, we view alerts as workflows, which consist of a series of steps executed in sequence, each with its own specific input and output. To keep our approach simple, Keep's syntax is designed to closely resemble the syntax used in GitHub Actions. We believe that GitHub Actions has a well-established syntax, and there is no need to reinvent the wheel.

## Full Example
```yaml
alert:
  id: raw-sql-query
  description: Monitor that time difference is no more than 1 hour
  steps:
    - name: get-max-datetime
      provider:
        type: mysql
        config: "{{ providers.mysql-prod }}"
        with:
          # Get max(datetime) from the random table
          query: "SELECT MAX(datetime) FROM demo_table LIMIT 1"
  actions:
    - name: trigger-slack
      condition:
      - type: threshold
        # datetime_compare(t1, t2) compares t1-t2 and returns the diff in hours
        #   utcnow() returns the local machine datetime in UTC
        #   to_utc() converts a datetime to UTC
        value: datetime_compare(utcnow(), to_utc({{ steps.get-max-datetime.results[0][0] }}))
        compare_to: 1 # hours
        compare_type: gt # greater than
        alias: A
      # redundant for "single step" example, but for "multi step" alerts this can be useful
      if: {{ A }}
      provider:
        type: slack
        config: " {{ providers.slack-demo }} "
        with:
          message: "DB datetime value ({{ steps.get-max-datetime.conditions.threshold[0].value }}) is greater than 1! 🚨"
```

## Breakdown 🔨
### Alert
```yaml
alert:
  id: raw-sql-query
  description: Monitor that time difference is no more than 1 hour
  steps:
    -
  actions:
    -
```

`Alert` is built of:
- Metadata (id, description. owners and tags will be added soon)
- `steps` - list of steps
- `actions` - list of actions

### Steps
```yaml
steps:
    - name: get-max-datetime
      provider:
      condition:
```
`Step` is built of:
  - `name` - the step name (context will be accessible through `{{ steps.name.results }}`).
  - `provider` - the data source.

### Provider
```yaml
provider:
    type: mysql
    config: "{{ providers.mysql-prod }}"
    with:
        # Get max(datetime) from the random table
        query: "SELECT MAX(datetime) FROM demo_table LIMIT 1"
```
`Provider` is built of:
- `type` - the type of the provider ([see supported providers](../022_providers/01-what-is-a-provider.md))
- `config` - the provider configuration. you can either supply it explicitly or using `"{{ providers.mysql-prod }}"`
- `with` - all type-specific provider configuration. for example, for `mysql` we will provide the SQL query.

### Condition
```yaml
condition:
- type: threshold
    # datetime_compare(t1, t2) compares t1-t2 and returns the diff in hours
    #   utcnow() returns the local machine datetime in UTC
    #   to_utc() converts a datetime to UTC
    value: datetime_compare(utcnow(), to_utc({{ steps.this.results[0][0] }}))
    compare_to: 1 # hours
    compare_type: gt # greater than
```
`Condition` is built of:
- `type` - the type of the condition
- `value` - the value that will be supplied to the condition during the alert execution
- `compare_to` - whats `value` will be compared against
- `compare_type` - all type-specific condition configuration

### Actions
```yaml
actions:
- name: trigger-slack
  # OPTIONAL: trigger the action only if both conditions are met:
  if: "{{ A }} or {{ B }}"
  # OPTIONAL: throttle the action according to some throttling strategy
  throttle:
        type: one_until_resolved
  # OPTIONAL: list of conditions that states if the action should be triggered
  condition:
  - type: threshold
    # datetime_compare(t1, t2) compares t1-t2 and returns the diff in hours
    #   utcnow() returns the local machine datetime in UTC
    #   to_utc() converts a datetime to UTC
    value: keep.datetime_compare(keep.utcnow(), keep.to_utc("{{ steps.this.results[0][0] }}"))
    compare_to: 1 # hours
    compare_type: gt # greater than
  # The provider that triggers the action using the "notify" function
  provider:
    type: slack
    config: " {{ providers.slack-demo }} "
    with:
      message: "DB datetime value ({{ actions.trigger-slack.conditions.threshold.0.compare_value }}) is greater than 1! 🚨"
```

#### * The last part of the alert are the actions.

`Action` is built of:
- `name` - the name of the action.
- `condition` - a list of conditions that
- `provider` - the provider that will trigger the action.
- `throttle` - you can [throttle](../025_throttles/01-what-is-throttle.md) the action.
- `if` - action can be limited to when certain [conditions](../023_conditions/01-what-is-a-condition.md) are met.
- `foreach` - when `foreach` block supplied, Keep will evaluate it as a list, and evaluates the `action` for every item in the list.

The `provider` configuration is already covered in [Providers](syntax#provider)
