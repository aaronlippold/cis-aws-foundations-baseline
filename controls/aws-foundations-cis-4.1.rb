control "aws-foundations-cis-4.1" do
  title "Ensure unauthorized API calls are monitored "
  desc "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch
Logs, or an external Security information and event management (SIEM) environment, and
establishing corresponding metric filters and alarms.

It is recommended that a metric
filter and alarm be established for unauthorized API calls. "
  desc "rationale",
       "Monitoring unauthorized API calls will help reduce time to detect malicious activity and can
alert you to a potential security incident.

CloudWatch is an AWS native service that
allows you to observe and monitor resources and applications. CloudTrail Logs can also be
sent to an external Security information and event management (SIEM) environment for
monitoring and alerting. "
  desc "check",
       "If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at
least one active multi-region CloudTrail with prescribed metric filters and alarms
configured:

1. Identify the log group name configured for use with active multi-region
CloudTrail:

- List all CloudTrails: `aws cloudtrail describe-trails`

- Identify
Multi region Cloudtrails: `Trails with \"IsMultiRegionTrail\" set to true`

- From value
associated with \"Name\":` note `<cloudtrail__name>`

- From value associated with
\"CloudWatchLogsLogGroupArn\" note <cloudtrail_log_group_name>

Example: for
CloudWatchLogsLogGroupArn that looks like
arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*,
<cloudtrail_log_group_name> would be NewGroup

- Ensure Identified Multi region
CloudTrail is active

`aws cloudtrail get-trail-status --name <Name of a Multi-region
CloudTrail>`

ensure `IsLogging` is set to `TRUE`

- Ensure identified Multi-region
Cloudtrail captures all Management Events

`aws cloudtrail get-event-selectors
--trail-name <\"Name\" as shown in describe-trails>`

Ensure there is at least one Event
Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set
to `All`

2. Get a list of all associated metric filters for this
`<cloudtrail_log_group_name>` that you captured in step 1:

```
aws logs
describe-metric-filters --log-group-name \"<cloudtrail_log_group_name>\"
```

3.
Ensure the output from the above command contains the
following:

```
\"filterPattern\": \"{ ($.errorCode =\"*UnauthorizedOperation\") ||
($.errorCode =\"AccessDenied*\") &&
($.sourceIPAddress!=\"delivery.logs.amazonaws.com\") && ($.eventName!=\"HeadBucket\")
}\",
```

4. Note the \"filterName\" `<unauthorized_api_calls_metric>` value
associated with the `filterPattern` found in step 3.

5. Get a list of CloudWatch alarms
and filter on the `<unauthorized_api_calls_metric>` captured in step 4.

```
aws
cloudwatch describe-alarms --query \"MetricAlarms[?MetricName ==
`unauthorized_api_calls_metric`]\"
```

6. Note the `AlarmActions` value - this will
provide the SNS topic ARN value.

7. Ensure there is at least one active subscriber to the
SNS topic

```
aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>

```
at least one subscription should have \"SubscriptionArn\" with valid aws
ARN.

```
Example of valid \"SubscriptionArn\": \"arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>\"
``` "
  desc "fix",
       "If you are using CloudTrails and CloudWatch, perform the following to setup the metric
filter, alarm, SNS topic, and subscription:

1. Create a metric filter based on filter
pattern provided which checks for unauthorized API calls and the
`<cloudtrail_log_group_name>` taken from audit step 1.
```
aws logs
put-metric-filter --log-group-name \"cloudtrail_log_group_name\" --filter-name
\"<unauthorized_api_calls_metric>\" --metric-transformations metricName=unauthorized_api_calls_metric,metricNamespace=CISBenchmark,metricValue=1
--filter-pattern \"{ ($.errorCode =\"*UnauthorizedOperation\") || ($.errorCode
=\"AccessDenied*\") && ($.sourceIPAddress!=\"delivery.logs.amazonaws.com\") &&
($.eventName!=\"HeadBucket\") }\"
```

**Note**: You can choose your own metricName and
metricNamespace strings. Using the same metricNamespace for all Foundations Benchmark
metrics will group them together.

2. Create an SNS topic that the alarm will
notify
```
aws sns create-topic --name <sns_topic_name>
```
**Note**: you can
execute this command once and then re-use the same topic for all monitoring
alarms.
**Note**: Capture the TopicArn displayed when creating the SNS Topic in Step
2.

3. Create an SNS subscription to the topic created in step 2
```
aws sns subscribe
--topic-arn <sns_topic_arn from step 2> --protocol <protocol_for_sns>
--notification-endpoint <sns_subscription_endpoints>
```

**Note**: you can
execute this command once and then re-use the SNS subscription for all monitoring
alarms.

4. Create an alarm that is associated with the CloudWatch Logs Metric Filter
created in step 1 and an SNS topic created in step 2
```
aws cloudwatch put-metric-alarm
--alarm-name \"unauthorized_api_calls_alarm\" --metric-name
\"unauthorized_api_calls_metric\" --statistic Sum --period 300 --threshold 1
--comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1
--namespace \"CISBenchmark\" --alarm-actions <sns_topic_arn>
``` "
  desc "additional_information",
       "Configuring log metric filter and alarm on Multi-region (global) CloudTrail
- ensures
that activities from all regions (used as well as unused) are monitored
- ensures that
activities on all supported global services are monitored
- ensures that all management
events across all regions are monitored "
  desc "impact",
       "This alert may be triggered by normal read-only console activities that attempt to
opportunistically gather optional information, but gracefully fail if they don't have
permissions.

If an excessive number of alerts are being generated then an organization
may wish to consider adding read access to the limited IAM user permissions simply to quiet the
alerts.

In some cases doing this may allow the users to actually view some areas of the
system - any additional access given should be reviewed for alignment with the original
limited IAM user intent. "
  impact 0.5
  ref "https://aws.amazon.com/sns/:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html:https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html:https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html"
  tag nist: %w[AU-6 AU-6(1) AU-7(1)]
  tag severity: "medium "
  tag cis_controls: [{ "8" => ["8.11"] }]

  pattern =
    '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'

  describe aws_cloudwatch_log_metric_filter(pattern: pattern) do
    it { should exist }
  end

  # Find the log_group_name associated with the aws_cloudwatch_log_metric_filter that has the pattern
  log_group_name =
    aws_cloudwatch_log_metric_filter(pattern: pattern).log_group_name

  # Find cloudtrails associated with with `log_group_name` parsed above
  associated_trails =
    aws_cloudtrail_trails.names.select do |x|
      aws_cloudtrail_trail(x).cloud_watch_logs_log_group_arn =~
        /log-group:#{log_group_name}:/
    end

  # Ensure log_group is associated atleast one cloudtrail
  describe "Cloudtrails associated with log-group: #{log_group_name}" do
    subject { associated_trails }
    it { should_not be_empty }
  end

  # Ensure atleast one of the associated cloudtrail meet the requirements.
  describe.one do
    associated_trails.each do |trail|
      describe aws_cloudtrail_trail(trail) do
        it { should be_multi_region_trail }
        it { should have_event_selector_mgmt_events_rw_type_all }
        it { should be_logging }
      end
    end
  end

  # Parse out `metric_name` and `metric_namespace` for the specified pattern.
  associated_metric_filter =
    aws_cloudwatch_log_metric_filter(
      pattern: pattern,
      log_group_name: log_group_name
    )
  metric_name = associated_metric_filter.metric_name
  metric_namespace = associated_metric_filter.metric_namespace

  # Ensure aws_cloudwatch_alarm for the specified pattern meets requirements.
  if associated_metric_filter.exists?
    describe aws_cloudwatch_alarm(
               metric_name: metric_name,
               metric_namespace: metric_namespace
             ) do
      it { should exist }
      its("alarm_actions") { should_not be_empty }
    end

    aws_cloudwatch_alarm(
      metric_name: metric_name,
      metric_namespace: metric_namespace
    ).alarm_actions.each do |sns|
      describe aws_sns_topic(sns) do
        it { should exist }
        its("confirmed_subscription_count") { should cmp >= 1 }
      end
    end
  end
end
