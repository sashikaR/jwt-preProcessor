# JWT-PreProcessor
A Jmeter pre-processor plugin. 

## Overview
This is a pre-processor plugin to generate Java Web Token (JWT). When a JWT requires as a pre-requisite
to send a HTTP request, this plugin can generate the JWT based on the details provided by
the user. The JWT token is store in a Jmeter variable which can use in other samplers.

### Step to use JWT-PreProcessor

1. Install the plugin in Jmeter
2. Add JWT-PreProcessor into the desired sampler
3. Set the details for JWT 
4. Use the variable whenever the JWT is required.

#### 1. Install Plugin
    a - Download the jar file and copy into your <your-jmeter-folder>/lib/ext location and restart the
        jmeter.
    c - Download the project and execute mvn clean package command and it will build the jar in target.
        Note - You need to have install Java and Maven in your develpment enviorment. This pulgin is build
        and tested in JDK 17 and Jmeter 5.5 and 5.6 versions.

#### 2. Add JWT-PreProcessor into HTTP sampler

    a - Create a Thread Group.
    b - Add the HTTP Sampler Add->Pre Processors->JWT PreProcessor
    ![My Image](images/image-1.png)

#### 3. Set Details
    a - Select the required algorithm for signing. 
            HS256 - HMAC with SHA-256, Symmetric Key Algorithm
            RS256 - RSA Signature with SHA-256, Assymetric Key Algorithm which uses Private Key/ Public Key
            No-SIgn - When signing is not requred.
    b - Give the Secret Key in the text field.
            If you select algorithm as HS256 then secret key is the Symmentric Key.
            If you select algorithm as RS256 then secret key is the Provate Key.
            Keep the text field as blank, when you do not need to sign.
    ![My Image](images/image-2.png)

    c - Add custom header attributes into the JWT token. The is an optional field. You can click Add button
        to inseert new row into the table. Inputs are taken as Key - Value pair.
    ![My Image](images/image-3.png)

    d - Add JWT payload data. In this table you can not change the payload attrinutes, only values are 
        allowed to insert here, however values are not mandatory to add. The values associate with dates
        should follow the given format.
    ![My Image](images/image-4.png)

    e - Any custom attribute requires to add in to the payload, you can set it in JWT Claims table. This
        is also optional to insert the values. 
    ![My Image](images/image-5.png)

    f - Give the variable name to use in the text field. The generated Java Web Token will be stored as
        Jmeter variable which is given here. 
    ![My Image](images/image-6.png)

    g - Sample jmx file(sample-test-plan.jmx) is copied in the project folder.


#### 4. How to Use

    a - Add Http Header Manager into the HTTP Sampler request. Create a one header request as token and 
        give the Jwt Variable as the value.
    ![My Image](images/image-7.png)

    b - Run the test plan and in the results tree listener then select the Http Request -> under Request
        tab select http. Then you can see the generated token.
    ![My Image](images/image-8.png)

    c - To verify the details paste the token in https://jwt.io/ 
     ![My Image](images/image-9.png)


