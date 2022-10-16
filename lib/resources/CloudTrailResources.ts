import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_s3 as s3 } from 'aws-cdk-lib';
import { aws_cloudtrail as trail } from 'aws-cdk-lib';
import { aws_logs as cwl } from 'aws-cdk-lib';
import { aws_iam as iam } from 'aws-cdk-lib';
import { aws_kms as kms } from 'aws-cdk-lib';

export class CloudTrailResources {
  // ログの監視で使用するためエクスポート
  public readonly cloudTrailLogGroup: cwl.LogGroup;


  constructor(scope: Construct) {
    // ----------------------- 設定値 ------------------------------
    // CloudTrailバケットへのサーバーアクセスログを記録
    const serverAccessLogBucket = new s3.Bucket(scope, 'ServerAccessLogBucket', {
      bucketName: 'server-access-log-bucket', //TODO バケットネーム変更
      accessControl: s3.BucketAccessControl.LOG_DELIVERY_WRITE,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      enforceSSL: true,
      lifecycleRules: [
        {
          enabled: true,
          expiration: cdk.Duration.days(1825), //5年間保存
        },
      ],
    });
    // オブジェクトの削除は禁止する
    serverAccessLogBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'Restrict Delete* Actions',
        effect: iam.Effect.DENY,
        actions: ['s3:Delete*'],
        principals: [new iam.AnyPrincipal()],
        resources: [serverAccessLogBucket.arnForObjects('*')],
      }),
    );

    // CloudTrail用のバケット
    const cloudTrailBucket = new s3.Bucket(scope, 'CloudTrailBucket', {
      bucketName: 'cloudtrail', //TODO バケットネーム変更
      accessControl: s3.BucketAccessControl.PRIVATE,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      serverAccessLogsBucket: serverAccessLogBucket,
      serverAccessLogsPrefix: 'cloudtraillogs',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      enforceSSL: true,
      lifecycleRules: [
        {
          enabled: true,
          expiration: cdk.Duration.days(1825), //5年間保存
        },
      ],
    });
    // オブジェクトの削除は禁止する
    cloudTrailBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'Restrict Delete* Actions',
        effect: iam.Effect.DENY,
        actions: ['s3:Delete*'],
        principals: [new iam.AnyPrincipal()],
        resources: [cloudTrailBucket.arnForObjects('*')],
      }),
    );

    // CMKを作成
    const cloudTrailKey = new kms.Key(scope, 'CloudTrailKey', {
      enableKeyRotation: true,
      description: 'for CloudTrail',
      alias: 'for-cloudtrail',
    });
    cloudTrailKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['kms:GenerateDataKey*'],
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        resources: ['*'],
        conditions: {
          StringLike: {
            'kms:EncryptionContext:aws:cloudtrail:arn': [`arn:aws:cloudtrail:*:${cdk.Stack.of(scope).account}:trail/*`],
          },
        },
      }),
    );
    cloudTrailKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['kms:DescribeKey'],
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        resources: ['*'],
      }),
    );
    cloudTrailKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Decrypt', 'kms:ReEncryptFrom'],
        principals: [new iam.AnyPrincipal()],
        resources: ['*'],
        conditions: {
          StringEquals: { 'kms:CallerAccount': `${cdk.Stack.of(scope).account}` },
          StringLike: {
            'kms:EncryptionContext:aws:cloudtrail:arn': [`arn:aws:cloudtrail:*:${cdk.Stack.of(scope).account}:trail/*`],
          },
        },
      }),
    );
    cloudTrailKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
        principals: [new iam.ServicePrincipal('logs.amazonaws.com')],
        resources: ['*'],
        conditions: {
          ArnEquals: {
            'kms:EncryptionContext:aws:logs:arn': `arn:aws:logs:ap-northeast-1:${cdk.Stack.of(scope).account
              }:log-group:*`, //TODO リージョン設定変更
          },
        },
      }),
    );

    // CloudWatch Logs Groupを作成
    const cloudTrailLogGroup = new cwl.LogGroup(scope, 'CloudTrailLogGroup', {
      retention: cwl.RetentionDays.THREE_MONTHS, //直近3ヶ月分のみ保持
      encryptionKey: cloudTrailKey,
    });
    this.cloudTrailLogGroup = cloudTrailLogGroup;

    // CloudTrailの設定を実施。
    new trail.Trail(scope, 'CloudTrail', {
      bucket: cloudTrailBucket,
      enableFileValidation: true,
      includeGlobalServiceEvents: true,
      cloudWatchLogGroup: cloudTrailLogGroup,
      encryptionKey: cloudTrailKey,
      sendToCloudWatchLogs: true,
    });


    // TODO Cloudtrailによるアラームを実装

    /*
    // LogGroup Construct for CloudTrail
      //   Use LogGroup.fromLogGroupName() because...
      //   On ControlTower environment, it created by not BLEA but ControlTower. So we need to refer existent LogGroup.
      //   When you use BLEA Standalone version, the LogGroup is created by BLEA.
      //
      //   Note:
      //     MetricFilter-based detection may delay for several minutes because of latency on CloudTrail Log delivery to CloudWatchLogs
      //     Use CloudWatch Events if you can, it deliver CloudTrail event faster.
      //     IAM event occur in us-east-1 region so if you want to detect it, you need to use MetrifFilter-based detection
      //     See: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
      //
      const cloudTrailLogGroup = cwl.LogGroup.fromLogGroupName(this, 'CloudTrailLogGroup', props.cloudTrailLogGroupName);

      // IAM Policy Change Notification
      //  from NIST template
      const mfIAMPolicyChange = new cwl.MetricFilter(this, 'IAMPolicyChange', {
        logGroup: cloudTrailLogGroup,
        filterPattern: {
          logPatternString:
            '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}',
        },
        metricNamespace: 'CloudTrailMetrics',
        metricName: 'IAMPolicyEventCount',
        metricValue: '1',
      });

      new cw.Alarm(this, 'IAMPolicyChangeAlarm', {
        metric: mfIAMPolicyChange.metric({
          period: cdk.Duration.seconds(300),
          statistic: cw.Statistic.SUM,
        }),
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription: 'IAM Configuration changes detected!',
        actionsEnabled: true,
      }).addAlarmAction(new cwa.SnsAction(secTopic));

      // Unauthorized Attempts
      //  from NIST template
      const mfUnauthorizedAttempts = new cwl.MetricFilter(this, 'UnauthorizedAttempts', {
        logGroup: cloudTrailLogGroup,
        filterPattern: {
          // Exclude calls “Decrypt" event by config.amazonaws.com to ignore innocuous errors caused by AWS Config.
          // That error occurs if you have KMS (CMK) encrypted environment variables in Lambda function.
          logPatternString:
            '{($.errorCode = "*UnauthorizedOperation" || $.errorCode = "AccessDenied*") && ($.eventName != "Decrypt" || $.userIdentity.invokedBy != "config.amazonaws.com" )}',
        },
        metricNamespace: 'CloudTrailMetrics',
        metricName: 'UnauthorizedAttemptsEventCount',
        metricValue: '1',
      });

      new cw.Alarm(this, 'UnauthorizedAttemptsAlarm', {
        metric: mfUnauthorizedAttempts.metric({
          period: cdk.Duration.seconds(300),
          statistic: cw.Statistic.SUM,
        }),
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 5,
        comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription: 'Multiple unauthorized actions or logins attempted!',
        actionsEnabled: true,
      }).addAlarmAction(new cwa.SnsAction(secTopic));

      // NewAccessKeyCreated
      //  from NIST template
      const mfNewAccessKeyCreated = new cwl.MetricFilter(this, 'NewAccessKeyCreated', {
        logGroup: cloudTrailLogGroup,
        filterPattern: {
          logPatternString: '{($.eventName=CreateAccessKey)}',
        },
        metricNamespace: 'CloudTrailMetrics',
        metricName: 'NewAccessKeyCreatedEventCount',
        metricValue: '1',
      });

      new cw.Alarm(this, 'NewAccessKeyCreatedAlarm', {
        metric: mfNewAccessKeyCreated.metric({
          period: cdk.Duration.seconds(300),
          statistic: cw.Statistic.SUM,
        }),
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription: 'Warning: New IAM access Eey was created. Please be sure this action was neccessary.',
        actionsEnabled: true,
      }).addAlarmAction(new cwa.SnsAction(secTopic));

      // Detect Root Activity from CloudTrail Log (For SecurityHub CIS 1.1)
      // See: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-standards-cis-controls-1.1
      // See: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail-additional-examples.html
      const mfRooUserPolicy = new cwl.MetricFilter(this, 'RootUserPolicyEventCount', {
        logGroup: cloudTrailLogGroup,
        filterPattern: {
          logPatternString:
            '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
        },
        metricNamespace: 'CloudTrailMetrics',
        metricName: 'RootUserPolicyEventCount',
        metricValue: '1',
      });

      new cw.Alarm(this, 'RootUserPolicyEventCountAlarm', {
        metric: mfRooUserPolicy.metric({
          period: cdk.Duration.seconds(300),
          statistic: cw.Statistic.SUM,
        }),
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        threshold: 1,
        comparisonOperator: cw.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription: 'Root user activity detected!',
        actionsEnabled: true,
      }).addAlarmAction(new cwa.SnsAction(secTopic));

      */
  }


}