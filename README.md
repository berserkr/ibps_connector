# Simple Connector for the Hyperledger Fabric Node.js SDK and IBM Blockchain Platform - Starter Plan

This connector is based on two other repositories with HL examples:

1) [IBM Blockchain - Car Auction Network Fabric Node SDK](https://github.com/IBM/car-auction-network-fabric-node-sdk)

2) [Hyperledger Fabric Samples - Balance Transfer](https://github.com/hyperledger/fabric-samples/tree/release-1.2/balance-transfer)

## Intro

The example core consists of four key files:

1) `config.json` - Which contains configuration information necessary to connect to the right service endpoints.

2) `creds.json` - This are the credentials obtained from the IBP Starter Plan.

3) `app.js` - Implements the core logic for the node REST app.

4) `connection.js` - Implements a class that loads the profile and config information needed to create a connection to the IBP Starter Plan. It also provides a set of APIs to query the IBP Starter Plan.

## Assumptions

We make the following assumptions in this document:

1) You have an instance of the IBM Blockchain Platform Starter Plan running.
2) You have initialized your network, you will be working with the default channel (e.g., `defaultchannel`) created or have created a new channel and will make the adjustments as necessary.
3) You have uploaded your chaincode to the starter plan and instantiated it.

To create a network and get started with your own instance of
the IBM Blockchain Platform Starter Plan please visit [Getting Started](https://www.ibm.com/blockchain/getting-started).

For an end-to-end application running inside the starter plan also feel free
to see [IBM Blockchain - Car Auction Network Fabric Node SDK](https://github.com/IBM/car-auction-network-fabric-node-sdk).

# Steps

## Step 1. Clone the repo

The first thing we need to do is clone the repo on your local computer.

```bash
git clone https://github.com/berserkr/ibps_connector
```

Then, go ahead and go into the directory:

```bash
cd ibps_connector
```

## Step 2. Enroll App
 ![packageFile](/docs/enrollAdmin.gif)

First, we need to generate the necessary keys and certs from the Certificate Authority to prove our authenticity to the network.
To do this, we will go into our new IBM Blockchain Starter Plan network, and from the `Overview` Tab on the left, we will click on `Connection Profile` on the right-side of the page. Then click on `Raw JSON`.

Open up the `JSON` document as we will need to extract a few things from it:

1) `enrollId` - should be "admin"
2) `enrollSecret` - should be similar to "1dcab332aa"
3) `url` - should be similar to "nde288ef7dd7542d3a1cc824a02be67f1-org1-ca.us02.blockchain.ibm.com:31011"
4) `caName` - should be "org1CA"

You will need to populate the right parameters in the `config.json` file:

```json
{
    "channelName" : "defaultchannel",
    "peerName" : "org1-peer1",
    "chaincodeId" : "mycc",
    "adminId" : "admin",
    "adminSecret" : "1dcab332aa",
    "orgId" : "org1",
    "orgCAName" : "org1CA",
    "endpointURL" : "nde288ef7dd7542d3a1cc824a02be67f1-org1-ca.us02.blockchain.ibm.com:31011",
    "keyStoreName" : "hfc-key-store"
}
```

## Step 3. Update Service Credentials

Next, we need to download the credentials needed to access the network.
To do this, we will go into our new IBM Blockchain Starter Plan network, and from the `Overview` Tab on the left, we will click on `Connection Profile` on the right-side of the page. Then click on `Download`.

You will end up with a file named `creds_nc88cda81f7a341b9a96b6a9fb0f03c02_org1.json` or something similar, rename it `creds.json` and move it over to
the same directory where `config.json` and `app.js` reside.

## Step 4. Install the Codebase

Save your file, and run npm install:

```bash
npm install
```

## Step 5. Start the Node App

In the command line run:

```bash
node app
```

## Step 6. Running testAPI.sh

Next, you can exercise the server by running the `testAPI.sh` script. There
are a few things that need to be tweaked before hand.

### 6.1 - If there is no `admin` registered, the service will register the `admin` user for you. You may then use the get token endpoint to perform administrative tasks.

You can register new users via the `users` url:

```text
http://localhost:3000/users
```

Otherwise, to get an access token, you may call the `token` url:

```text
http://localhost:3000/token
```

Below is an example showing how to invoke the user registration url. Notice,
the name of the user we are getting a token for (e.g., `TestUser`).

```bash
############################### NOTE ###############################
# If testing with new user, please user http://localhost:3000/users
#   otherwise, keep it as http://localhost:3000/token
####################################################################
ORG1_TOKEN=$(curl -s -X POST \
  http://localhost:3000/token \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=TestUser&orgName=org1')
echo $ORG1_TOKEN
ORG1_TOKEN=$(echo $ORG1_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "ORG1 token is $ORG1_TOKEN"
```

### 6.2 - Assuming you have a default channel called `defaultchannel`, make sure that all `curl` calls use the right channel during invocation.

For example:

```text
http://localhost:3000/channels/defaultchannel/chaincodes/blooms
```

### 6.3 - Next, we need to make sure that the chaincode name is updated, for instance, if your target chaincode is `mycc`, make sure that all calls that require some interaction with the chaincode have `mycc` (replace it with your chaincode name).

For example:

```text
http://localhost:3000/channels/defaultchannel/chaincodes/mycc
```

# Links

* [IBM Blockchain - Car Auction Network Fabric Node SDK](https://github.com/IBM/car-auction-network-fabric-node-sdk)
* [Hyperledger Fabric Samples - Balance Transfer](https://github.com/hyperledger/fabric-samples/tree/release-1.2/balance-transfer)
* [IBM Blockchain - Marbles demo](https://github.com/IBM-Blockchain/marbles)
* [Hyperledger Fabric Docs](https://hyperledger-fabric.readthedocs.io/en/release-1.2/)

# Learn more

* **Blockchain Code Patterns**: Enjoyed this Code Pattern? Check out our other [Blockchain Code Patterns](https://developer.ibm.com/code/technologies/blockchain/)

* **Blockchain 101**: Learn why IBM believes that blockchain can transform businesses, industries – and even the world. [Blockchain 101](https://developer.ibm.com/code/technologies/blockchain/)

# License
[Apache 2.0](LICENSE)
