/**
 * Copyright 2018 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const _ = require("lodash/fp")
const lodashOO = require("lodash")
const net = require("net")
const fs = require("fs")
const path = require("path")
const FabricClient = require("fabric-client")
const Orderer = require("fabric-client/lib/Orderer")
const fcw = require("fabric-client-wrapper")

const { mapValues } = lodashOO

/**
 * Utility function to replace all the values in a JSON object that look like
 * relative paths, into absolute paths
 * @param {JSON} config - The object that represents a configuration.
 * @param {refPath} refPath - A string that represents the path to be taken
 * @param {key} key - A key that represents a key asssociated with the configuration
 * relative from .
 * @returns {JSON} - Returns the configuration with the relative paths.
 */
function makeNetworkConfigRelativePathsAbsolute(config, refPath, key) {
    const makeAbsoluteFilePathKeys = [
        "genesisBlock",
        "tx",
        "tlsca",
        "keystore",
        "signcerts"
    ]
    if (makeAbsoluteFilePathKeys.includes(key)) {
        if (_.isArray(config)) {
            return config.map(string => path.resolve(refPath, string))
        }
        return path.resolve(refPath, config)
    }
    if (!_.isObject(config)) {
        return config
    }
    if (_.isArray(config)) {
        return config.map(elem =>
            makeNetworkConfigRelativePathsAbsolute(elem, refPath)
        )
    }
    return mapValues(config, (v, k) =>
        makeNetworkConfigRelativePathsAbsolute(v, refPath, k)
    )
}

async function parseOrganizationsJSON(organizationsJSON, ownJSON) {
    const own = {
        admins: {},
        members: {},
        peers: []
    }

    const organizations = await Promise.all(
        organizationsJSON.map(async organizationJSON => {
            const { mspId, tlsca: tlscaPath } = organizationJSON
            const peersJSON = organizationJSON.peers || []
            const organization = {
                peers: []
            }

            if (mspId === ownJSON.mspId) {
                own.config = {
                    cryptoSuite: FabricClient.newCryptoSuite(),
                    mspId
                }

                await Promise.all(
                    ownJSON.users.map(async userJSON => {
                        const keystoreFileName = fs.readdirSync(
                            userJSON.keystore
                        )[0]
                        const signCertFileName = fs.readdirSync(
                            userJSON.signcerts
                        )[0]
                        const privateKeyPEM = fs
                            .readFileSync(
                                path.join(userJSON.keystore, keystoreFileName)
                            )
                            .toString()
                        const signedCertPEM = fs
                            .readFileSync(
                                path.join(userJSON.signcerts, signCertFileName)
                            )
                            .toString()
                        const user = await fcw.newUserClientFromKeys({
                            ...own.config,
                            username: userJSON.username,
                            cryptoContent: {
                                privateKeyPEM,
                                signedCertPEM
                            },
                            roles: [userJSON.role]
                        })

                        if (userJSON.role === fcw.ADMIN_ROLE) {
                            own.admins[userJSON.username] = user
                        } else {
                            own.members[userJSON.username] = user
                        }
                    })
                )
            }

            const admin = Object.values(own.admins)[0]
            let tlscaPem
            if (tlscaPath) {
                tlscaPem = Buffer.from(fs.readFileSync(tlscaPath)).toString()
            }
            peersJSON.forEach(peerJSON => {
                const connectionOpts = tlscaPem
                    ? {
                          pem: tlscaPem,
                          "ssl-target-name-override":
                              peerJSON["server-hostname"]
                      }
                    : {}
                const peerId = peerJSON.url.split("//")[1]

                let peer
                if (ownJSON.peers.includes(peerId)) {
                    peer = admin.newEventHubPeer({
                        requestUrl: peerJSON.url,
                        eventUrl: peerJSON.eventUrl,
                        peerOpts: connectionOpts,
                        eventHubOpts: connectionOpts
                    })
                    own.peers.push(peer)
                } else {
                    peer = fcw.newFcwPeer({
                        mspId,
                        requestUrl: peerJSON.url,
                        peerOpts: connectionOpts
                    })
                }
                organization.peers.push(peer)
            })
            return organization
        })
    )
    return {
        own,
        organizations
    }
}

function parseOrganizationsJSONForOrderer(organizationsJSON, ordererId) {
    const ordererFilterLambda = ordererJSON =>
        ordererJSON.url.includes(ordererId)
    const ordererOrganizationJSON = organizationsJSON.find(
        organizationJSON =>
            organizationJSON.orderers &&
            organizationJSON.orderers.find(ordererFilterLambda)
    )
    const ordererPeerJSON = ordererOrganizationJSON.orderers.find(
        ordererFilterLambda
    )

    if (!ordererOrganizationJSON.tlsca) {
        return new Orderer(ordererPeerJSON.url)
    }

    const tlscaPem = Buffer.from(
        fs.readFileSync(ordererOrganizationJSON.tlsca)
    ).toString()

    return new Orderer(ordererPeerJSON.url, {
        "ssl-target-name-override": ordererPeerJSON["server-hostname"],
        pem: tlscaPem
    })
}

function createCreateChannelOpts(admin, channelConfigEnvelope) {
    const config = admin.extractChannelConfig(channelConfigEnvelope)
    const signatures = [admin.signChannelConfig(config)]

    return {
        config,
        signatures
    }
}

async function installChaincode(organizations, chaincodesJSON, admin) {
    // eventhub peers are owned by the current organisation
    const myPeers = _.flatten(
        organizations.map(organization => organization.peers || [])
    ).filter(peer => fcw.isEventHubPeer(peer))

    return Promise.all(
        chaincodesJSON.map(chaincodeJSON =>
            admin
                .installChaincode({
                    targets: myPeers,
                    chaincodeId: chaincodeJSON.id,
                    chaincodeVersion: chaincodeJSON.version,
                    chaincodePath: chaincodeJSON.path,
                    chaincodeType: chaincodeJSON.chaincodeType
                })
                .catch(error => {
                    // ignore already installed error
                    if (!error.message.match(/\(chaincode [^\b]+ exists\)/)) {
                        throw error
                    }
                })
        )
    )
}

async function parseChannelChaincodeJSON(
    organizations,
    channelsJSON,
    chaincodesJSON,
    endorsementPoliciesJSON,
    organizationsJSON,
    orgNetworkConfigJSON,
    admin
) {
    const orderers = {}
    // create channel objects
    const channels = (await Promise.all(
        channelsJSON.map(async channelJSON => {
            const { orderers: ordererIds, peers: peerIds } = channelJSON

            const channelPeerFilterLambda = peer =>
                peerIds.some(peerId => peer.getUrl().includes(peerId))
            const peers = _.flatten(
                organizations.map(organization => organization.peers)
            ).filter(channelPeerFilterLambda)

            if (
                !peers.some(
                    peer => peer.getMspId() === orgNetworkConfigJSON.mspId
                )
            ) {
                return null
            }

            const ordererId = ordererIds[0] // NOTE ignoring all orderers except the first one at the moment.
            let orderer
            if (orderers[ordererId]) {
                orderer = orderers[ordererId]
            } else {
                orderer = parseOrganizationsJSONForOrderer(
                    organizationsJSON,
                    ordererId
                )
            }

            const maxPeerRetryTimes = 10
            const eventHubPeers = peers.filter(peer => fcw.isEventHubPeer(peer))

            eventHubPeers.forEach(peer => {
                console.log(
                    `Channel: ${
                        channelJSON.name
                    }, Event Hub Peer: ${peer.getUrl()}`
                )
            })

            let connected = false
            for (let i = 0; i < maxPeerRetryTimes; i++) {
                // eslint-disable-next-line no-await-in-loop
                const canConnectResults = await Promise.all(
                    eventHubPeers.map(peer =>
                        peer.getEventHubManager().canConnect()
                    )
                )
                if (canConnectResults.every(result => result)) {
                    connected = true
                    break
                }
                canConnectResults.forEach((result, index) => {
                    console.log(
                        `Peer ${eventHubPeers[index]} connected: ${result}`
                    )
                })
                const peerRetryWait = 1000 * (i + 1)
                console.log(
                    `Could not connect to own peers, retrying in ${
                        peerRetryWait
                    }ms`
                )

                // eslint-disable-next-line no-await-in-loop
                await new Promise(resolve => setTimeout(resolve, peerRetryWait))
            }

            if (!connected) {
                throw new Error("Error: Could not connect to own peers")
            }

            const channel = fcw.newEventHubChannel({
                userClient: admin,
                channelName: channelJSON.name,
                peers,
                orderers: [orderer],
                eventHubManager: eventHubPeers[0].getEventHubManager()
            })

            connected = false
            // hack to check if orderer is up. TODO replace if cleaner solution is found
            const maxOrdererRetryTimes = 10
            for (let i = 0; i < maxOrdererRetryTimes; i++) {
                try {
                    // eslint-disable-next-line no-await-in-loop
                    await admin.createChannel(channel, {
                        config: Buffer.from(""),
                        signatures: []
                    })
                } catch (error) {
                    if (error.message.includes("BAD_REQUEST")) {
                        connected = true
                        break
                    }
                    const ordererRetryWait = 1000 * (i + 1)
                    // eslint-disable-next-line no-await-in-loop
                    await new Promise(resolve =>
                        setTimeout(resolve, ordererRetryWait)
                    )
                }
            }
            if (!connected) {
                throw new Error(
                    `Error: Could not connect to Orderer ${ordererId}`
                )
            }
            return channel
        })
    )).filter(channel => channel)

    // checks if all chaincode is instantiated on all channels
    const chaincodeInstantiated = (await Promise.all(
        channels.map(async (channel, i) => {
            const channelJSON = channelsJSON[i]
            const channelChaincodesJSON = channelJSON.chaincodes
            const instantiatedArray = await Promise.all(
                channelChaincodesJSON.map(
                    chaincodeJSON =>
                        admin
                            .isChaincodeInstantiated(channel, chaincodeJSON.id)
                            .catch(error => false) // ignore error
                )
            )
            return instantiatedArray.every(Boolean)
        })
    )).every(Boolean)

    if (chaincodeInstantiated) {
        console.log(
            `${orgNetworkConfigJSON.mspId} Network already bootstrapped`
        )
    } else {
        await installChaincode(organizations, chaincodesJSON, admin)
        const { leader, host } = orgNetworkConfigJSON.networkSetup
        const port = orgNetworkConfigJSON.port || 12345
        if (!leader) {
            const retryTimes = 10
            let connected = false
            for (let i = 0; i < retryTimes; i++) {
                try {
                    // eslint-disable-next-line no-await-in-loop
                    await new Promise((resolve, reject) => {
                        const client = net.connect(port, host)
                        client.on("error", error => reject(error))
                        client.on("connect", () => resolve())
                    })
                    connected = true
                    break
                } catch (error) {
                    if (error.message.includes("ECONNREFUSED")) {
                        const wait = 1000 * (i + 1)
                        // console.log(
                        //     `Client could not connect, retrying in: ${wait}ms`
                        // )

                        // eslint-disable-next-line no-await-in-loop
                        await new Promise(resolve => setTimeout(resolve, wait))
                    } else {
                        throw error
                    }
                }
            }
            if (!connected) {
                throw new Error("Error: Client failed to connect to leader")
            }
        }

        // reuse TCP socket for all channels
        let channelSetupServer
        let channelSetupClient
        if (leader) {
            channelSetupServer = new fcw.ChannelSetupServer({
                port
            })
        } else {
            channelSetupClient = new fcw.ChannelSetupClient({
                host,
                port
            })
        }

        // setup network
        // TODO allow network to be bootstrapped in parallel. Need to fix issue where can't instantiate same chaincode on multiple channels at the same time
        for (let i = 0; i < channels.length; i++) {
            const channel = channels[i]
            const channelJSON = channelsJSON[i]
            const channelChaincodesJSON = channelJSON.chaincodes
            const createChannelOpts = createCreateChannelOpts(
                admin,
                fs.readFileSync(channelJSON.tx)
            )

            if (leader) {
                // hack to check if orderer is up. TODO replace if cleaner solution is found
                const maxOrdererRetryTimes = 10
                for (let j = 0; j < maxOrdererRetryTimes; j++) {
                    try {
                        // eslint-disable-next-line no-await-in-loop
                        const createChannelRes = await admin.createChannel(
                            channel,
                            createChannelOpts
                        )
                        // eslint-disable-next-line no-await-in-loop
                        await createChannelRes.wait()
                    } catch (error) {
                        if (error.message.includes("SERVICE_UNAVAILABLE")) {
                            const ordererRetryWait = 1000 * (j + 1)
                            // eslint-disable-next-line no-await-in-loop
                            await new Promise(resolve =>
                                setTimeout(resolve, ordererRetryWait)
                            )
                        } else {
                            break
                        }
                    }
                }
            }

            // console.log("channelJSON", channelJSON)
            // console.log("createChannelOpts", createChannelOpts)

            const channelSetup = fcw
                .setupChannel(admin, channel, {
                    network: {
                        leader,
                        channelSetupServer,
                        channelSetupClient
                    },
                    swallowAlreadyCreatedErrors: true
                })
                .withCreateChannel(createChannelOpts)
                .withJoinChannel()

            channelChaincodesJSON.forEach(channelChaincodeJSON => {
                const chaincodeJSON = chaincodesJSON.find(
                    ({ id }) => id === channelChaincodeJSON.id
                )
                channelSetup.withInstantiateChaincode(
                    {
                        chaincodeId: channelChaincodeJSON.id,
                        chaincodeVersion: chaincodeJSON.version,
                        fcn: channelChaincodeJSON.instantiate.fcn,
                        args: channelChaincodeJSON.instantiate.args,
                        targets: channelChaincodeJSON.instantiationPolicy,
                        "endorsement-policy":
                            endorsementPoliciesJSON[
                                channelChaincodeJSON.endorsementPolicy
                            ]
                    },
                    {
                        timeout: 5 * 60000
                    }
                )
            })
            // eslint-disable-next-line no-await-in-loop
            await channelSetup.run()
            if (leader) {
                console.log(`Channel ${channelJSON.name} setup`)
            }
        }
        if (leader) {
            channelSetupServer.close()
        } else {
            channelSetupClient.destroy()
        }
    }

    const endorsementPolicies = {}
    channelsJSON.forEach(channelJSON => {
        const channelChaincodesJSON = channelJSON.chaincodes
        const channelEndorsementPolicies = {}
        channelChaincodesJSON.forEach(chaincodeJSON => {
            channelEndorsementPolicies[chaincodeJSON.id] =
                endorsementPoliciesJSON[chaincodeJSON.endorsementPolicy]
        })
        endorsementPolicies[channelJSON.name] = channelEndorsementPolicies
    })

    return {
        channels: _.keyBy(o => o.getName())(channels),
        endorsementPolicies,
        chaincodes: _.keyBy(o => o.id)(chaincodesJSON)
    }
}

function substituteVariables(configString, substitutionMap) {
    let result = configString
    Object.entries(substitutionMap).forEach(([key, value]) => {
        result = result.replace(new RegExp(`\\\${${key}}`, "g"), value)
    })
    return result
}

function loadNetworkConfig(filepath, substitutionMap) {
    const dirpath = filepath.substring(
        0,
        Math.max(filepath.lastIndexOf("/"), filepath.lastIndexOf("\\"))
    )
    const config = JSON.parse(
        substituteVariables(
            fs.readFileSync(filepath).toString(),
            substitutionMap
        )
    )
    return makeNetworkConfigRelativePathsAbsolute(config, dirpath)
}

async function networkBootstrap(
    commonNetworkConfigPath,
    orgNetworkConfigPath,
    substitutionMap
) {
    const {
        channels: channelsJSON,
        chaincodes: chaincodesJSON,
        endorsementPolicy: endorsementPolicyJSON,
        organizations: organizationsJSON
    } = loadNetworkConfig(commonNetworkConfigPath, substitutionMap)
    const orgNetworkConfigJSON = loadNetworkConfig(
        orgNetworkConfigPath,
        substitutionMap
    )

    const {
        own: { admins, config },
        organizations
    } = await parseOrganizationsJSON(organizationsJSON, orgNetworkConfigJSON)

    const {
        channels,
        endorsementPolicies,
        chaincodes
    } = await parseChannelChaincodeJSON(
        organizations,
        channelsJSON,
        chaincodesJSON,
        endorsementPolicyJSON || {},
        organizationsJSON,
        orgNetworkConfigJSON,
        admins.admin
    )

    return {
        admins,
        config,
        channels,
        endorsementPolicies,
        chaincodes
    }
}

networkBootstrap.loadNetworkConfig = loadNetworkConfig

module.exports = networkBootstrap
