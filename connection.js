/*
 Copyright 2018 IBM All Rights Reserved.
 Licensed under the Apache License, Version 2.0 (the 'License');
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an 'AS IS' BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

'use strict';
var log4js = require('log4js');
var logger = log4js.getLogger('IBPConnector');
var creds = require('./creds.json'); // credentials downloaded from IBP
var config = require('./config.json'); // configuration file
var FabClient = require('fabric-client');
var FabricCAClient = require('fabric-ca-client');
var path = require('path');
var util = require('util');

/**
 * This class provide a connection to the IBP through the use of a user's
 *  credentals (creds.json). This connector will work over single
 *  channel and peer intances. The channel and peer information is 
 *  pulled from the config.json file. 
 */
class IBPConnecton {

    /**
     * Constructor. Initialize all class variables to null.
     */
    constructor() {
        this.adminId = null;
        this.peerName = null;
        this.chaincodeId = null;
        this.adminId = null;
        this.orgId = null;
        this.endpointURL = null;
        this.fabCAClient = null;
        this.fabClient = null;
        this.channel = null;
        this.peer = null;
        this.order = null;
    }

    
    ///////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// INITIALIZATION LOGIC /////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * Loads parameters from configuration file (config.json)
     */
    loadParameters() {
        this.channelName = config.channelName;
        this.peerName = config.peerName;
        this.chaincodeId = config.chaincodeId;
        this.adminId = config.adminId;
        this.orgId = config.orgId;
        this.adminSecret = config.adminSecret;
        this.orgCAName = config.orgCAName;
        this.endpointURL = config.endpointURL;
        this.keyStoreName = config.keyStoreName;

        logger.debug('Parameters loaded [%s, %s, %s, %s, %s]',
            this.channelName, this.peerName, this.chaincodeId, 
            this.adminId, this.orgId);
    } // end load parameters

    /**
     * Initialize the basic Fabric Client. This client instance is
     *  used by all the APIs.
     */
    initClient() {

        this.fabClient = new FabClient();

        // We assume we will work over one channel only.
        this.channel = this.fabClient.newChannel(this.channelName);

        // And we will connect to a single peer instance.
        this.peer = this.fabClient.newPeer(
            creds.peers[this.peerName].url, 
            { pem: creds.peers[this.peerName].tlsCACerts.pem, 
                'ssl-target-name-override': null });
        this.channel.addPeer(this.peer);
        this.order = this.fabClient.newOrderer(
            creds.orderers.orderer.url, 
            { pem: creds.orderers.orderer.tlsCACerts.pem, 
                'ssl-target-name-override': null });
        this.channel.addOrderer(this.order);

        logger.debug('Fabric client initialized...')
    } // end init

    /**
     * We will open up the keystore here
     * @param {*} keyStoreName 
     */
    initKeyStore(keyStoreName) {
        this.storePath = path.join(__dirname, keyStoreName);
        this.stateStore = null;

        // create the key value store as defined in the fabric-client/config/default.json 'key-value-store' setting
        FabClient.newDefaultKeyValueStore({
            path: this.storePath
        }).then((stateStore) => {
            // assign the store to the fabric client
            this.fabClient.setStateStore(stateStore);
            var cryptoSuite = FabClient.newCryptoSuite();

            // use the same location for the state store (where the users' certificate are kept)
            // and the crypto store (where the users' keys are kept)
            var cryptoStore = FabClient.newCryptoKeyStore({ path: this.storePath });
            cryptoSuite.setCryptoKeyStore(cryptoStore);
            this.fabClient.setCryptoSuite(cryptoSuite);

            var url = 'https://' + this.adminId + ':' + 
            this.adminSecret + '@' + this.endpointURL;

            this.fabCAClient = new FabricCAClient(
                url, null, this.orgCAName, cryptoSuite);

            logger.debug('Loaded keystore from ' + keyStoreName);
        });
        
    } // end init key store

    /**
     * This method is intended to initialize the admin instance...
     *  TODO: See if it is redundant.
     */
    initAdmin() {
        // load administrator...
        var admin = this.getUserCreds(this.adminId, false);
        var adminId = this.adminId;
        var secret = this.adminSecret;
        var orgId = this.orgId;

        if(admin && admin.isEnrolled()) {
            logger.debug(`${adminId} is loaded, no need to enroll it.`)
        }
        else {

            this.fabCAClient.enroll({
                enrollmentID: adminId,
                enrollmentSecret: secret
            }).then((enrollment) => {
                return this.fabClient.createUser({
                    username: adminId,
                    mspid: orgId,
                    cryptoContent: { 
                        privateKeyPEM: enrollment.key.toBytes(), 
                        signedCertPEM: enrollment.certificate }
                }).then((adminUser) => {
                    // now set it as the context...
                    admin = adminUser;
                    return this.fabClient.setUserContext(admin).then(() => {
                        logger.debug('Assigned the admin user to the fabric client ::' + 
                        admin.toString());    
                    });
                });
            }).catch((err) => {
                logger.error('Failed to enroll and persist admin. Error: ' + 
                    err.stack ? err.stack : err);
                throw new Error('Failed to enroll admin');
            });
        }
    } // end initAdmin

    /**
     * Main service initialization logic.
     */
    init() {
        this.loadParameters();
        this.initClient();
        
        this.storePath = path.join(__dirname, this.keyStoreName);
        this.stateStore = null;

        logger.debug('Loading keystore data from ' + this.keyStoreName);

        // create the key value store as defined in the fabric-client/config/default.json 'key-value-store' setting
        FabClient.newDefaultKeyValueStore({
            path: this.storePath
        }).then((stateStore) => {
            // assign the store to the fabric client
            this.fabClient.setStateStore(stateStore);
            var cryptoSuite = FabClient.newCryptoSuite();

            // use the same location for the state store (where the users' certificate are kept)
            // and the crypto store (where the users' keys are kept)
            var cryptoStore = FabClient.newCryptoKeyStore({ path: this.storePath });
            cryptoSuite.setCryptoKeyStore(cryptoStore);
            this.fabClient.setCryptoSuite(cryptoSuite);

            var url = 'https://' + this.adminId + ':' + 
                this.adminSecret + '@' + this.endpointURL;

            logger.debug('CA URL: %s, with CA Name: %s', url, this.orgCAName);

            this.fabCAClient = new FabricCAClient(
                url, null, this.orgCAName, cryptoSuite);

            logger.debug('Loaded keystore from ' + this.keyStoreName);

            return this.fabClient.getUserContext(this.adminId, true);

        }).then((admin) => {

            var adminId = this.adminId;
            var secret = this.adminSecret;
            var orgId = this.orgId;
            
            // check if the admin user is enrolled...
            if(admin && admin.isEnrolled()) {
                logger.debug(`${adminId} is loaded, no need to enroll it.`)
            }
            else {

                // no admin user, let's create it...
                this.fabCAClient.enroll({
                    enrollmentID: adminId,
                    enrollmentSecret: secret
                }).then((enrollment) => {
                    return this.fabClient.createUser({
                        username: adminId,
                        mspid: orgId,
                        cryptoContent: { 
                            privateKeyPEM: enrollment.key.toBytes(), 
                            signedCertPEM: enrollment.certificate }
                    }).then((adminUser) => {
                        // now set it as the context...
                        admin = adminUser;
                        return this.fabClient.setUserContext(admin).then(() => {
                            logger.debug('Assigned the admin user to the fabric client ::' + 
                            admin.toString());    
                        });
                    });
                }).catch((err) => {
                    logger.error('Failed to enroll and persist admin. Error: ' + 
                        err.stack ? err.stack : err);
                    throw new Error('Failed to enroll admin');
                });
            }
        });
        //this.initAdmin();
        logger.debug('Done with initialization...')
    }

        
    ///////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// CREDENTIALS //////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    // TODO: check if needed, might be redundant...
    /**
     * 
     * @param {*} user 
     */
    getUserCreds(user, isJson) {
        return this.fabClient.getUserContext(user, true).then((userCreds) => {
            if (userCreds && userCreds.isEnrolled()) {
                logger.debug(`Successfully loaded ${user} from key store`);

                if(isJson) {
                    var response = {
                        success: true,
                        message: user + ' enrolled Successfully',
                    };

                    return response;
                }
                else {
                    return userCreds;
                }
            } else if(userCreds && !userCreds.isEnrolled()) {
                throw new Error(`User ${user} is not enrolled. \
                    Please delete user and re-enroll.`);
            } 
            else {
                throw new Error(`Failed to get ${user}.... \
                    run <url to service>/registerUser`);
            }
        }).catch((err) => {
            logger.error('Failed to get user credentials. Error: ' + 
                err.stack ? err.stack : err);
            throw new Error('Failed to get user credentials.');
        });
    } // end getUserCreds

    /**
     * 
     * @param {*} user 
     * @param {*} org 
     * @param {*} isJson
     */
    registerUser(user, org, isJson) {
        /*
        ORG1_TOKEN=$(curl -s -X POST \
            http://localhost:3000/users \
            -H "content-type: application/x-www-form-urlencoded" \
            -d 'username=Luis&orgName=org1')
          echo $ORG1_TOKEN
        */

        // Don't want to rely on promises, so we will make most calls synchronous

        var adminUser = null;
        var memberUser = null;
        var status = '';
        var message = 'FAIL';
        //var userEnrollmentSecret = null;

        return this.fabClient.getUserContext(this.adminId, true).then((user_from_store) => {
            if (user_from_store && user_from_store.isEnrolled()) {
                logger.debug(`Successfully loaded ${user_from_store} from persistence`);
                adminUser = user_from_store;
            } else {
                throw new Error('Failed to get admin.... run enrollAdmin.js');
            }
            return this.fabCAClient.register({enrollmentID: user, affiliation: org, role: 'client'}, adminUser);
        }).then((secret) => {
            logger.debug('Successfully registered user with secret:'+ secret);
            //userEnrollmentSecret = secret;
            return this.fabCAClient.enroll({enrollmentID: user, enrollmentSecret: secret});
        }).then((enrollment) => {
            logger.debug('Successfully enrolled member user: ' + user);
            return this.fabClient.createUser(
                {username: user, mspid: org,
                    cryptoContent: { 
                        privateKeyPEM: enrollment.key.toBytes(), 
                        signedCertPEM: enrollment.certificate 
                    }
                });
        }).then((newUser) => {
            memberUser = newUser;
            return this.fabClient.setUserContext(memberUser);
        }).then((theUser)=>{
            status = 'SUCCESS';
            message = `${user} was successfully registered and enrolled and is ready to interact with the fabric network`;
            logger.debug(message);
            
            if(theUser && theUser.isEnrolled()) {

                // disable sending back the secret...
                // is it necessary?
                if(status=='SUCCESS' && isJson) {
                    var response = {
                        success: true,
                        //secret: userEnrollmentSecret,
                        message: message,
                    };
                    
                    return response;
                }
                else {

                    return message;
                }
            }
            else {
                throw new Error('User was not enrolled ');
            }

        }).catch((err) => {
            message = 'Failed to register: ' + err;
            logger.error(message);
            if(err.toString().indexOf('Authorization') > -1) {
                var message2 = 'Authorization failures may be caused by having admin credentials from a previous CA instance.\n \
                    Try again after deleting the contents of the store directory ' 
                    + this.storePath;

                logger.error(message2);
                message = message + '\n' + message2;
            }

            return message;
        });
    } // end registerUser

        
    ///////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// CHAINCODE APIs ///////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * 
     * @param {*} user 
     * @param {*} chainId 
     * @param {*} chaincodeId 
     * @param {*} fcn 
     * @param {*} args 
     */
    invokeChaincode(user, chainId, chaincodeId, fcn, args) {

        /*
        Calling the code as follows:
        TRX_ID=$(curl -s -X POST \
            http://localhost:3000/channels/defaultchannel/chaincodes/blooms \
            -H "authorization: Bearer $ORG1_TOKEN" \
            -H "content-type: application/json" \
            -d '{
              "fcn":"write",
              "args":["key", "value"]
          }')
        */
        logger.debug('Invoking %s/%s/%s with args=%s, for %s', chainId,
            chaincodeId, fcn, args, user);

        // create transaction id
        var txid = null;
        var message = '';
        var status = 'FAIL';

        // sanity check...
        if(user && chainId && chaincodeId && fcn && args) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                    return userCreds;
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return null;
            }).then((theUser) => {

                txid = this.fabClient.newTransactionID();
                logger.debug('Transaction ID: ' + txid._transaction_id);
                    
                var request = {
                    chaincodeId: chaincodeId,
                    fcn: fcn,
                    args: args,
                    chainId : chainId,
                    txId: txid
                };

                return this.channel.sendTransactionProposal(request);

            }).then((results) => {
                var proposalResponses = results[0];
                var proposal = results[1];
                let isProposalGood = false;
                if (proposalResponses && proposalResponses[0].response &&
                    proposalResponses[0].response.status === 200) {
                    isProposalGood = true;
                    logger.debug('Transaction proposal was good');
                } else {
                    logger.error(results);
                }
                if (isProposalGood) {
                    logger.debug(util.format(
                        'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s"',
                        proposalResponses[0].response.status, proposalResponses[0].response.message));
                
                    // build up the request for the orderer to have the transaction committed
                    var request = {
                        proposalResponses: proposalResponses,
                        proposal: proposal
                    };
                
                    // set the transaction listener and set a timeout of 30 sec
                    // if the transaction did not get committed within the timeout period,
                    // report a TIMEOUT status
                    var transaction_id_string = txid.getTransactionID(); //Get the transaction ID string to be used by the event processing
                    var promises = [];
                
                    var sendPromise = this.channel.sendTransaction(request);
                    promises.push(sendPromise); //we want the send transaction first, so that we know where to check status
                
                    // get an eventhub once the fabric client has a user assigned. The user
                    // is required bacause the event registration must be signed
                    let event_hub = this.channel.newChannelEventHub(this.peer);
                
                    // using resolve the promise so that result status may be processed
                    // under the then clause rather than having the catch clause process
                    // the status
                    let txPromise = new Promise((resolve, reject) => {
                        let handle = setTimeout(() => {
                            event_hub.unregisterTxEvent(transaction_id_string);
                            event_hub.disconnect();
                            resolve({ event_status: 'TIMEOUT' }); //we could use reject(new Error('Trnasaction did not complete within 30 seconds'));
                        }, 3000);
                        event_hub.registerTxEvent(transaction_id_string, (tx, code) => {
                            // this is the callback for transaction event status
                            // first some clean up of event listener
                            clearTimeout(handle);
                    
                            // now let the application know what happened
                            var return_status = { 
                                event_status: code, 
                                txid: transaction_id_string 
                            };

                            if (code !== 'VALID') {
                                logger.error('The transaction was invalid, code = ' + code);
                                resolve(return_status); // we could use reject(new Error('Problem with the tranaction, event status ::'+code));
                            } else {
                                logger.debug('The transaction has been committed on peer ' + event_hub.getPeerAddr());
                                resolve(return_status);
                            }
                        }, (err) => {
                            //this is the callback if something goes wrong with the event registration or processing
                            reject(new Error('There was a problem with the eventhub ::' + err));
                        },
                        { disconnect: true } //disconnect when complete
                        );
                        event_hub.connect();
                
                    });
                    promises.push(txPromise);
                
                    return Promise.all(promises);
                } else {
                    logger.error('Failed to send Proposal or receive valid response. \
                        Response null or status is not 200. exiting...');
                    throw new Error('Failed to send Proposal or receive valid response. \
                        Response null or status is not 200. exiting...');
                }
            }).then((results) => {
                logger.debug('Send transaction promise and event listener promise have completed');
                // check the results in the order the promises 
                //  were added to the promise all list
                if (results && results[0] && results[0].status === 'SUCCESS') {
                    logger.debug('Successfully sent transaction to the orderer.');
                } else {
                    logger.error('Failed to order the transaction. Error code: ' + 
                        results[0].status);
                }
            
                if (results && results[1] && results[1].event_status === 'VALID') {
                    message = 'Successfully committed the change to the ledger by the peer';
                    status = 'SUCCESS';
                    logger.debug(message);

                    // Done with everything... let's return the txid
                    var response = {
                        txid : txid._transaction_id,
                        status : status,
                        message: message
                    }

                    return response;

                } else {
                    message = 'Transaction failed to be committed to the ledger due to ::' + 
                        results[1].event_status;
                    logger.debug(message);        
                    
                    // Done with everything... let's return the txid
                    var response = {
                        status : status,
                        message: message
                    }

                    return response;
                }

            }).catch((err) => {
                message = 'Failed to invoke successfully :: ' + err;
                logger.error(message);
            });
        }
        else {
            message = 'Failed to invoke chaincode, missing required property in call.';
            logger.error(message);
        }

        // Done with everything... let's return the txid
        var response = {
            status : status,
            message: message
        }

        return response;
    } // end invoke chaincode


    /**
     * 
     * @param {*} user 
     * @param {*} chaincodeId 
     * @param {*} fcn
     * @param {*} args 
     */
    queryChaincode(user, chaincodeId, fcn, args) {
        /*
        curl -s -X GET \
            "http://localhost:3000/channels/defaultchannel/chaincodes/blooms?fcn=read&args=%5B%22key%22%5D" \
            -H "authorization: Bearer $ORG1_TOKEN" \
            -H "content-type: application/json"
        */

        // assume status failed, and initialize return message
        // return object is json in the format {status: status, message: message}
        var message = '';
        var status = 'FAIL';

        // sanity check...
        if(user && chaincodeId && fcn && args) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                    return userCreds;
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return null;
            }).then((theUser) => {
                    
                var request = {
                    chaincodeId: chaincodeId,
                    fcn: fcn,
                    args: args
                };

                return this.channel.queryByChaincode(request);
            
            }).then((queryResults) => {

                logger.debug(`${fcn} call has completed, checking results`);
                // queryResults could have more than one  results if there multiple peers were used as targets
                if (queryResults && queryResults.length == 1) {
                    if (queryResults[0] instanceof Error) {
                        
                        message = 'error from query ' + queryResults[0];
                        logger.error(message);

                    } else {
                        logger.debug('Response is ', queryResults[0].toString());
                        message = queryResults[0].toString();
                        status = 'SUCCESS';
                    }
                } else {
                    message = 'No payloads were returned from query';
                    logger.debug(message);
                }

                // all done!!!! Let's return the response...
                var response = {
                    status: status,
                    message: message
                };
        
                return response;

            }).catch((err) => {
                    message = 'Failed to query successfully :: ' + err;
                    logger.error(message);
            }); // end query
        }
        else {
            message = 'Failed to invoke chaincode, missing required property in call.'
            logger.error(message);            
        }

        var response = {
            status: status,
            message: message
        };

        return response;
    } // end query chaincode


        
    ///////////////////////////////////////////////////////////////////////////////
    //////////////////////////////// BLOCKCHAIN APIs //////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * 
     * @param {*} user 
     * @param {*} blockNumber 
     */
    getBlockByNumber(user, blockNumber) {

        if(user && blockNumber) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.channel.queryBlock(parseInt(blockNumber, this.peer));
            }).then((responsePayload) => {
                if(responsePayload) {
                    logger.debug(responsePayload);
                    return responsePayload;
                }
                else {
                    logger.error('response_payload is null');
                    return 'response_payload is null';
                }
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    }

    /**
     * 
     * @param {*} user 
     * @param {*} trxnID 
     */
    getTransactionByID(user, trxnID) {
        if(user && trxnID) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.channel.queryTransaction(trxnID, this.peer);
            }).then((responsePayload) => {
                if(responsePayload) {
                    logger.debug(responsePayload);
                    return responsePayload;
                }
                else {
                    logger.error('response_payload is null');
                    return 'response_payload is null';
                }
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // end get transaction by id

    /**
     * 
     * @param {*} user 
     * @param {*} hash 
     */
    getBlockByHash(user, hash) {
        if(user && hash) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.channel.queryBlockByHash(Buffer.from(hash), this.peer);
            }).then((responsePayload) => {
                if(responsePayload) {
                    logger.debug(responsePayload);
                    return responsePayload;
                }
                else {
                    logger.error('response_payload is null');
                    return 'response_payload is null';
                }
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // get block by hash

    /**
     * 
     * @param {*} user 
     */
    getChainInfo(user) {
        if(user) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.channel.queryInfo(this.peer);
            }).then((responsePayload) => {
                if(responsePayload) {
                    logger.debug(responsePayload);
                    return responsePayload;
                }
                else {
                    logger.error('response_payload is null');
                    return 'response_payload is null';
                }
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // get chain info


    //getInstalledChaincodes
    //TODO: make sure to invoke this with the admin user
    /**
     * 
     * @param {*} user 
     */
    getInstalledChaincodes(user) {
        if(user) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.fabClient.queryInstalledChaincodes(this.peer, true);
            }).then((response) => {
                logger.debug('<<< Installed Chaincodes >>>');
                var details = [];
                for (let i = 0; i < response.chaincodes.length; i++) {
                    logger.debug('name: ' + response.chaincodes[i].name + ', version: ' +
                        response.chaincodes[i].version + ', path: ' + response.chaincodes[i].path
                    );
                    details.push('name: ' + response.chaincodes[i].name + ', version: ' +
                        response.chaincodes[i].version + ', path: ' + response.chaincodes[i].path
                    );
                }
                return details;
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // end query for installed chaincodes

    /**
     * 
     * @param {*} user 
     */
    getInstantiatedChaincodes(user) {
        if(user) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.channel.queryInstantiatedChaincodes(this.peer, true);
            }).then((response) => {
                logger.debug('<<< Instantiated Chaincodes >>>');
                var details = [];
                for (let i = 0; i < response.chaincodes.length; i++) {
                    logger.debug('name: ' + response.chaincodes[i].name + ', version: ' +
                        response.chaincodes[i].version + ', path: ' + response.chaincodes[i].path
                    );
                    details.push('name: ' + response.chaincodes[i].name + ', version: ' +
                        response.chaincodes[i].version + ', path: ' + response.chaincodes[i].path
                    );
                }
                return details;
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // end get instantiated cc

    /**
     * 
     * @param {*} user 
     */
    getChannels(user) {
        if(user) {

            // first, set user context...
            return this.fabClient.getUserContext(user, true).then((userCreds) => {
                if (userCreds && userCreds.isEnrolled()) {
                    logger.debug(`Successfully loaded ${user} from key store`);
                } else if(!userCreds.isEnrolled()) {
                    throw new Error(`User ${user} is not enrolled. \
                        Please delete user and re-enroll.`);
                } 
                else {
                    throw new Error(`Failed to get ${user}.... \
                        run <url to service>/registerUser`);
                }
                return this.fabClient.queryChannels(this.peer);
            }).then((response) => {
                if (response) {
                    logger.debug('<<< channels >>>');
                    var channelNames = [];
                    for (let i = 0; i < response.channels.length; i++) {
                        channelNames.push('channel id: ' + response.channels[i].channel_id);
                    }
                    logger.debug(channelNames);
                    return response;
                } else {
                    logger.error('response_payloads is null');
                    return 'response_payloads is null';
                }
            }).catch((error => {
                logger.error('Failed to query due to error: ' + error.stack ? error.stack : error);
                return error.toString();
            }));
        }
        else {
            message = 'Failed to query the channel, missing required property in call.';
            logger.error(message);
            return message;
        }
    } // end get channels
    

} // class IBP



///////////////////////////////////////////////////////////////////////////////
////////////////////////////////// EXPORTS ////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

module.exports = IBPConnecton;