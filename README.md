# AWSIAM

AWS IAM Interface for Julia

[![Build Status](https://travis-ci.org/samoconnor/AWSIAM.jl.svg)](https://travis-ci.org/samoconnor/AWSIAM.jl)

```julia
using AWSIAM

aws = AWSCore.aws_config()

println(iam_whoami(aws))

creds = iam_create_user(aws, "my_user")


@protected try

    iam(aws, Action = "CreateRole",
             Path = "/",
             RoleName = name,
             AssumeRolePolicyDocument = """{
                "Version": "2012-10-17",
                "Statement": [ {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                } ]
             }""")

catch e
    @ignore if e.code == "EntityAlreadyExists" end
end

iam(aws, Action = "PutRolePolicy",
         RoleName = name,
         PolicyName = name,
         PolicyDocument = Policy)

@protected try 

    iam(aws, Action = "CreateInstanceProfile",
             InstanceProfileName = name,
             Path = "/")
catch e
    @ignore if e.code == "EntityAlreadyExists" end
end


@repeat 2 try 

    iam(aws, Action = "AddRoleToInstanceProfile",
             InstanceProfileName = name,
             RoleName = name)

catch e
    @retry if e.code == "LimitExceeded"
        iam(aws, Action = "RemoveRoleFromInstanceProfile",
                 InstanceProfileName = name,
                 RoleName = name)
    end
end
```
