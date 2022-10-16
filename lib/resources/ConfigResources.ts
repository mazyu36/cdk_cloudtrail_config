
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_config as config } from 'aws-cdk-lib';
import { aws_iam as iam } from 'aws-cdk-lib';
import { aws_s3 as s3 } from 'aws-cdk-lib';

export class ConfigResources {

  constructor(scope: Construct) {

    // IAMロールを作成
    const role = new iam.Role(scope, 'ConfigRole', {
      assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWS_ConfigRole')],
    });

    // 設定変更を記録
    new config.CfnConfigurationRecorder(scope, 'ConfigRecorder', {
      roleArn: role.roleArn,
      recordingGroup: {
        allSupported: true,
        includeGlobalResourceTypes: true,
      },
    });


    // 設定変更記録用のバケットを作成
    const bucket = new s3.Bucket(scope, 'ConfigBucket', {
      bucketName: 'config-buckst', //TODO バケットネーム変更
      accessControl: s3.BucketAccessControl.PRIVATE,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          enabled: true,
          expiration: cdk.Duration.days(1825),
        },
      ],
    });

    // バケットポリシーを設定
    bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [role],
        resources: [bucket.bucketArn],
        actions: ['s3:GetBucketAcl'],
      }),
    );

    bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [role],
        resources: [bucket.arnForObjects(`AWSLogs/${cdk.Stack.of(scope).account}/Config/*`)],
        actions: ['s3:PutObject'],
        conditions: {
          StringEquals: {
            's3:x-amz-acl': 'bucket-owner-full-control',
          },
        },
      }),
    );

    // Configの設定変更をバケットに配信
    new config.CfnDeliveryChannel(scope, 'ConfigDeliveryChannel', {
      s3BucketName: bucket.bucketName,
    });
  }
}