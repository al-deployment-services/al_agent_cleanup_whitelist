
Delete AlertLogic Agent via API in Lambda
============================================
Sample usage of AlertLogic API to remove al-agent registration in AlertLogic portal.
This function natively available in AlertLogic console for AWS customer, unless if:

* You don't deploy the Cloud Defender Support IAM role cross account
* You deploy in AWS Gov Cloud

AlertLogic API end-point used in the script:

* Cloud Defender API (https://docs.alertlogic.com/developer/)

Requirements
--------------------
* AWS credentials with sufficient permission to deploy Lambda, IAM roles, SNS, KMS key and launch Cloud Formation (optional)
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Defender API (API KEY)

Usage
---------------
1. Request the Cloud Defender API key, if you don't have one available click [here](https://www.alertlogic.com/resources/alert-logic-activeintegration-apis/)
2. Use the Cloud Formation [here](/cloud_formation) and launch the stack
3. Specify the AWS tag value that you wish to use as whitelist
4. Specify if AWS region if you want to limit the scope

Contributing
-------------------
Since this is just an example, the script will be provided AS IS, with no long-term support.
