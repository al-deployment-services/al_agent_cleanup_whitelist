Cloud Formation to deploy al_agent_cleanup_whitelist
=======================================================
This CloudFormation will launch 2 lambda function, the encryption helper lambda (to encrypt environment variables) and the main function to remove offline AL Agents.

Supported Region
-----------------
Currently the Lambda package only available in the following regions:

 - us-east-1
 - us-east-2
 - us-west-1
 - us-west-2
 - eu-central-1
 - eu-west-1
 - eu-west-2
 - eu-west-3

Non-supported Region
---------------------
To launch the stack in alternative regions, please do the following:

 1. Create new S3 bucket in the target region
 2. Use the following format when creating the new S3 bucket:  `bucket-name.region-name`
 3. Download the Lambda package from [here](/lambda/al_agent_cleanup_whitelist.zip)
 4. Upload the Lambda package to `lambda_packages/al_agent_cleanup_whitelist.zip`
 5. Launch the stack and point to your new S3 bucket name
