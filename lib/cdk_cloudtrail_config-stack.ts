import { CloudTrailResources } from './resources/CloudTrailResources';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { ConfigResources } from './resources/ConfigResources';
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export class CdkCloudtrailConfigStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new CloudTrailResources(this)
    new ConfigResources(this)
  }
}
