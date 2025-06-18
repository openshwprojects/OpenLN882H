#include <assert.h>

#include "core_mqtt.h"
#include "core_mqtt_state.h"

#include "logging_levels.h"
#include "logging_stack.h"

#include "network_transport.h"
#include "backoff_algorithm.h"
#include "clock.h"

#include "osal/osal.h"
#include "netif/ethernetif.h"
#include "utils/debug/log.h"
#include "utils/debug/ln_assert.h"

#include "mqtt_client.h"

typedef enum 
{
    MQTT_CLI_EVT_SUBSCRIBE         = 0,
    MQTT_CLI_EVT_UNSUBSCRIBE       = 1,
    MQTT_CLI_EVT_PUBLISH           = 2,
    MQTT_CLI_EVT_CONN              = 3,
    MQTT_CLI_EVT_DISCONN           = 4,
} mqtt_evt_id_t;

typedef struct {
    uint16_t  evt_id;
    uint16_t  len;
    void     *buffer;
} mqtt_evt_t;

/**
 * Provide default values for undefined configuration settings.
 */
#ifndef NETWORK_BUFFER_SIZE
    #define NETWORK_RX_BUFFER_SIZE    ( 1500U )
    #define NETWORK_TX_BUFFER_SIZE    ( 1500U )
#endif


#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )//The maximum number of retries for connecting to server.
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 1000U )//The maximum back-off delay (in milliseconds) for retrying connection to server.
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 300U )//The base back-off delay (in milliseconds) to use for connection retry attempts.
#define CONNACK_RECV_TIMEOUT_MS                  1500//( 1000U )//Timeout for receiving CONNACK packet in milli seconds.


/**
 * @brief Maximum number of outgoing publishes maintained in the application until an ack is received from the broker.
 */
#define MAX_OUTGOING_PUBLISHES             50//10// ( 5U )

#define MQTT_PACKET_ID_INVALID              ( ( uint16_t ) 0U ) //Invalid packet ID for the MQTT packets. 
#define MQTT_PROCESS_LOOP_TIMEOUT_MS        ( 500U ) //Timeout for MQTT_ProcessLoop function in milliseconds.
//#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    60//30//( 60U )
#define DELAY_BETWEEN_PUBLISHES_SECONDS     ( 1U )
#define MQTT_PUBLISH_COUNT_PER_LOOP         60000 //( 5U )
#define MQTT_SUBPUB_LOOP_DELAY_SECONDS      1//( 5U )


/*-----------------------------------------------------------*/
static OS_Thread_t g_mqtt_thread;
#define MQTT_TASK_STACK_SIZE   (4096)

static OS_Thread_t g_mqtt2_thread;
#define MQTT2_TASK_STACK_SIZE   2048//1024

static OS_Queue_t mqtt_evt_queue;
#define  MQTT_EVT_MSG_QUEUE_SIZE  (30)

static OS_Mutex_t g_mqtt_api_lock = {0};

static bool mqtt_auto_reconnect = true;

static mqtt_client_cfg_t *mqtt_cli_cfg = NULL;

int mqtt_evt_msg_recv(void *mqtt_evt, uint32_t timeout);


/*-----------------------------------------------------------*/
/**
 * @brief Structure to keep the MQTT publish packets until an ack is received for QoS1 publishes.
 */
typedef struct PublishPackets
{
    uint16_t          packetId;
    MQTTPublishInfo_t pubInfo;
} PublishPackets_t;

/*-----------------------------------------------------------*/
/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker;
 * it is used to match received Subscribe ACK to the transmitted subscribe.
 */
static uint16_t globalSubscribePacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker;
 * it is used to match received Unsubscribe ACK to the transmitted unsubscribe
 * request.
 */
static uint16_t globalUnsubscribePacketIdentifier = 0U;

/**
 * @brief Array to keep the outgoing publish messages.
 * These stored outgoing publish messages are kept until a successful ack
 * is received.
 */
static PublishPackets_t outgoingPublishPackets[ MAX_OUTGOING_PUBLISHES ] = { 0 };

/**
 * @brief Array to keep subscription topics.
 * Used to re-subscribe to topics that failed initial subscription attempts.
 */
static MQTTSubscribeInfo_t pGlobalSubscriptionList[ 1 ];

/**
 * @brief The network buffer must remain valid for the lifetime of the MQTT context.
 */
static uint8_t g_mqtt_network_rx_buffer[ NETWORK_RX_BUFFER_SIZE ];
static uint8_t g_mqtt_network_tx_buffer[ NETWORK_TX_BUFFER_SIZE ];

/**
 * @brief Status of latest Subscribe ACK;
 * it is updated every time the callback function processes a Subscribe ACK
 * and accounts for subscription to a single topic.
 */
static MQTTSubAckStatus_t globalSubAckStatus = MQTTSubAckFailure;

/*-----------------------------------------------------------*/
static int  connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext, MQTTContext_t * pMqttContext, bool * pClientSessionPresent, bool * pBrokerSessionPresent );
static void handleIncomingPublish( MQTTPublishInfo_t * pPublishInfo, uint16_t packetIdentifier );
static void eventCallback( MQTTContext_t * pMqttContext, MQTTPacketInfo_t * pPacketInfo, MQTTDeserializedInfo_t * pDeserializedInfo );
static int  initializeMqtt( MQTTContext_t * pMqttContext,  NetworkContext_t * pNetworkContext );

static int establishMqttSession ( MQTTContext_t * pMqttContext, bool createCleanSession, bool * pSessionPresent );
static int disconnectMqttSession( MQTTContext_t * pMqttContext );

static int subscribeToTopic     ( MQTTContext_t * pMqttContext, MQTTSubscribeInfo_t *subscribe_info );
static int unsubscribeFromTopic ( MQTTContext_t * pMqttContext, MQTTSubscribeInfo_t *unsubscribe_info);
static int publishToTopic       ( MQTTContext_t * pMqttContext, PublishPackets_t * pPublish);

static int  getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex );
static void cleanupOutgoingPublishAt( uint8_t index );
static void cleanupOutgoingPublishes( void );
static void cleanupOutgoingPublishWithPacketID( uint16_t packetId );

static void updateSubAckStatus( MQTTPacketInfo_t * pPacketInfo );

/*-----------------------------------------------------------*/
static uint32_t generateRandomNumber(void) {
    return OS_Rand32();
}

/*-----------------------------------------------------------*/
static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext, MQTTContext_t * pMqttContext, bool * pClientSessionPresent, bool * pBrokerSessionPresent )
{
    int returnStatus = EXIT_FAILURE;
    aws_ada_tls_status_e tls_status;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    BackoffAlgorithmContext_t reconnectParams;
    uint16_t nextRetryBackOff;
    bool createCleanSession;

    memset(pNetworkContext, 0, sizeof(*pNetworkContext));
    mqtt_client_cfg_t *cli = mqtt_cli_cfg;

    /* Initialize information to connect to the MQTT broker. */
    pNetworkContext->hostname = cli->hostname;
    pNetworkContext->port     = cli->port;

    pNetworkContext->server_root_ca_pem      = cli->server_root_ca_pem;
    pNetworkContext->server_root_ca_pem_size = cli->server_root_ca_pem == NULL ? 0 : strlen(cli->server_root_ca_pem);
    pNetworkContext->client_cert_pem         = cli->client_cert_pem;
    pNetworkContext->client_cert_pem_size    = cli->client_cert_pem == NULL ? 0 : strlen(cli->client_cert_pem);
    pNetworkContext->client_key_pem          = cli->client_key_pem;
    pNetworkContext->client_key_pem_size     = cli->client_key_pem == NULL ? 0 : strlen(cli->client_key_pem);

    pNetworkContext->alpn_protos = NULL;

    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams, CONNECTION_RETRY_BACKOFF_BASE_MS, CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS, CONNECTION_RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase until maximum attempts are reached. */
    do
    {
        LogInfo( ( "Establishing a TLS session to %.*s:%d.", strlen(pNetworkContext->hostname), pNetworkContext->hostname, pNetworkContext->port ) );
        tls_status = aws_ada_tls_conn(pNetworkContext);
        if( tls_status == AWS_ADA_TLS_STATUS_SUCCESS )
        {
            /* A clean MQTT session needs to be created, if there is no session saved in this MQTT client. */
            createCleanSession = ( *pClientSessionPresent == true ) ? false : true;

            /* Sends an MQTT Connect packet using the established TLS session, then waits for connection acknowledgment (CONNACK) packet. */
            returnStatus = establishMqttSession( pMqttContext, createCleanSession, pBrokerSessionPresent );

            if( returnStatus == EXIT_FAILURE )
            {
                /* End TLS session, then close TCP connection. */
                ( void ) aws_ada_tls_disconn( pNetworkContext );
            }
        }

        if( returnStatus == EXIT_FAILURE )
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                returnStatus = EXIT_FAILURE;
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection "
                           "after %hu ms backoff.", ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( returnStatus == EXIT_FAILURE ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex )
{
    int returnStatus = EXIT_FAILURE;
    uint8_t index = 0;

    assert( outgoingPublishPackets != NULL );
    assert( pIndex != NULL );

    for( index = 0; index < MAX_OUTGOING_PUBLISHES; index++ )
    {
        /* A free index is marked by invalid packet id. Check if the the index has a free slot. */
        if( outgoingPublishPackets[ index ].packetId == MQTT_PACKET_ID_INVALID )
        {
            returnStatus = EXIT_SUCCESS;
            break;
        }
    }

    /* Copy the available index into the output param. */
    *pIndex = index;

    return returnStatus;
}
/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishAt( uint8_t index )
{
    assert( outgoingPublishPackets != NULL );
    assert( index < MAX_OUTGOING_PUBLISHES );

    /* Clear the outgoing publish packet. */
    memset( &( outgoingPublishPackets[ index ] ), 0x00, sizeof( outgoingPublishPackets[ index ] ) );
}

/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishes( void )
{
    assert( outgoingPublishPackets != NULL );

    /* Clean up all the outgoing publish packets. */
    memset( outgoingPublishPackets, 0x00, sizeof( outgoingPublishPackets ) );
}

/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishWithPacketID( uint16_t packetId )
{
    uint8_t index = 0;

    assert( outgoingPublishPackets != NULL );
    assert( packetId != MQTT_PACKET_ID_INVALID );

    /* Clean up all the saved outgoing publishes. */
    for( ; index < MAX_OUTGOING_PUBLISHES; index++ )
    {
        if( outgoingPublishPackets[ index ].packetId == packetId )
        {
            cleanupOutgoingPublishAt( index );
            LogInfo( ( "Cleaned up outgoing publish packet with packet id %u.\r\n", packetId ) );
            break;
        }
    }
}

/*-----------------------------------------------------------*/
// 收到 消息推送
static void handleIncomingPublish( MQTTPublishInfo_t * pPublishInfo, uint16_t packetIdentifier )
{
    assert( pPublishInfo != NULL );

    /* Verify the received publish is for the topic we have subscribed to. */
    //TODO: LogInfo( ( "Incoming Publish Topic Name: %.*s does not match subscribed topic.", pPublishInfo->topicNameLength, pPublishInfo->pTopicName ) );
    if (mqtt_cli_cfg->incoming_pub_cb) {
        mqtt_cli_cfg->incoming_pub_cb((char*)(pPublishInfo->pTopicName), pPublishInfo->topicNameLength, (char*)(pPublishInfo->pPayload), pPublishInfo->payloadLength);
    }
}

/*-----------------------------------------------------------*/
//更新订阅 ACK 状态
static void updateSubAckStatus( MQTTPacketInfo_t * pPacketInfo )
{
    uint8_t * pPayload = NULL;
    size_t pSize = 0;

    MQTTStatus_t mqttStatus = MQTT_GetSubAckStatusCodes( pPacketInfo, &pPayload, &pSize );

    /* MQTT_GetSubAckStatusCodes always returns success if called with packet info from the event callback and non-NULL parameters. */
    assert( mqttStatus == MQTTSuccess );

    /* Demo only subscribes to one topic, so only one status code is returned. */
    globalSubAckStatus = ( MQTTSubAckStatus_t ) pPayload[ 0 ];
}

/*-----------------------------------------------------------*/
static void eventCallback( MQTTContext_t * pMqttContext, MQTTPacketInfo_t * pPacketInfo, MQTTDeserializedInfo_t * pDeserializedInfo )
{
    uint16_t packetIdentifier;

    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Suppress unused parameter warning when asserts are disabled in build. */
    ( void ) pMqttContext;

    packetIdentifier = pDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        /* Handle incoming publish. */
        handleIncomingPublish( pDeserializedInfo->pPublishInfo, packetIdentifier );
    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_SUBACK:

                /* A SUBACK from the broker, containing the server response to our subscription request, has been received.
                 * It contains the status code indicating server approval/rejection for the subscription to the single topic
                 * requested. The SUBACK will be parsed to obtain the status code, and this status code will be stored in global
                 * variable globalSubAckStatus. */
                updateSubAckStatus( pPacketInfo );

                /* Check status of the subscription request. If globalSubAckStatus does not indicate
                 * server refusal of the request (MQTTSubAckFailure), it contains the QoS level granted
                 * by the server, indicating a successful subscription attempt. */
                if( globalSubAckStatus != MQTTSubAckFailure )
                {
                    LogInfo( ( "Subscribed to the topic. with maximum QoS %u.", globalSubAckStatus) );
                }
			
                // /* Make sure ACK packet identifier matches with Request packet identifier. */
                // assert( globalSubscribePacketIdentifier == packetIdentifier );
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                LogInfo( ( "Unsubscribed from the topic.\r\n") );
                /* Make sure ACK packet identifier matches with Request packet identifier. */
                assert( globalUnsubscribePacketIdentifier == packetIdentifier );
                break;

            case MQTT_PACKET_TYPE_PINGRESP:

                /* Nothing to be done from application as library handles
                 * PINGRESP. */
                LogWarn( ( "PINGRESP should not be handled by the application " "callback when using MQTT_ProcessLoop.\r\n" ) );
                break;

            case MQTT_PACKET_TYPE_PUBACK:
                LogInfo( ( "PUBACK received for packet id %u.\r\n", packetIdentifier ) );
                /* Cleanup publish packet when a PUBACK is received. */
                cleanupOutgoingPublishWithPacketID( packetIdentifier );
                break;

            /* Any other packet type is invalid. */
            default:
                LogError( ( "Unknown packet type received:(%02x).\r\n", pPacketInfo->type ) );
        }
    }
}

/*-----------------------------------------------------------*/
static int establishMqttSession( MQTTContext_t * pMqttContext, bool createCleanSession, bool * pSessionPresent )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTConnectInfo_t connectInfo = { 0 };

    assert( pMqttContext != NULL );
    assert( pSessionPresent != NULL );

    /* Establish MQTT session by sending a CONNECT packet. */

    /* If #createCleanSession is true, start with a clean session
     * i.e. direct the MQTT broker to discard any previous session data.
     * If #createCleanSession is false, directs the broker to attempt to
     * reestablish a session which was already present. */
    connectInfo.cleanSession = createCleanSession;

    mqtt_client_cfg_t *cli = mqtt_cli_cfg;
    connectInfo.keepAliveSeconds       = cli->keepalive;
    connectInfo.pClientIdentifier      = cli->client_id;
    connectInfo.clientIdentifierLength = cli->client_id == NULL ? 0 : strlen(cli->client_id);
    connectInfo.pUserName              = cli->username;
    connectInfo.userNameLength         = cli->username == NULL ? 0 : strlen(cli->username);
    connectInfo.pPassword              = cli->password;
    connectInfo.passwordLength         = cli->password == NULL ? 0 : strlen(cli->password);

    MQTTPublishInfo_t *willInfo = NULL;
    if (cli->last_will_topic_name && cli->last_will_message)
    {
        willInfo = OS_Malloc(sizeof(MQTTPublishInfo_t));
        if (willInfo) {
            willInfo->qos    = MQTTQoS0;
            willInfo->retain = 0;
            willInfo->dup    = 0;
            willInfo->pTopicName      = cli->last_will_topic_name;
            willInfo->topicNameLength = strlen(cli->last_will_topic_name);
            willInfo->pPayload        = (const void * )cli->last_will_message;
            willInfo->payloadLength   = strlen(cli->last_will_message);
        }
    }
    
    /* Send MQTT CONNECT packet to broker. */
    mqttStatus = MQTT_Connect( pMqttContext, &connectInfo, willInfo, CONNACK_RECV_TIMEOUT_MS, pSessionPresent );

    if( mqttStatus != MQTTSuccess )  {
        returnStatus = EXIT_FAILURE;
        LogError( ( "Connection with MQTT broker failed with status %s.", MQTT_Status_strerror( mqttStatus ) ) );
    } else {
        LogInfo( ( "MQTT connection successfully established with broker.\r\n" ) );
    }

    return returnStatus;
}

static int disconnectMqttSession( MQTTContext_t * pMqttContext )
{
    MQTTStatus_t mqttStatus = MQTTSuccess;
    int returnStatus = EXIT_SUCCESS;

    assert( pMqttContext != NULL );

    mqttStatus = MQTT_Disconnect( pMqttContext );

    LogError( ( "Sending MQTT DISCONNECT with status=%s.", MQTT_Status_strerror( mqttStatus ) ) );
    if( mqttStatus != MQTTSuccess ) {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

static int subscribeToTopic( MQTTContext_t * pMqttContext, MQTTSubscribeInfo_t *subscribe_info )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;

    assert( pMqttContext != NULL );

    /* Start with everything at 0. */
    memset( pGlobalSubscriptionList, 0x00, sizeof( pGlobalSubscriptionList ) );

    /* This example subscribes to only one topic and uses QOS1. */
    pGlobalSubscriptionList[ 0 ].qos               = subscribe_info->qos;
    pGlobalSubscriptionList[ 0 ].pTopicFilter      = subscribe_info->pTopicFilter;
    pGlobalSubscriptionList[ 0 ].topicFilterLength = subscribe_info->topicFilterLength;

    /* Generate packet identifier for the SUBSCRIBE packet. */
    globalSubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

    /* Send SUBSCRIBE packet. */
    mqttStatus = MQTT_Subscribe( pMqttContext, pGlobalSubscriptionList, sizeof( pGlobalSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ), globalSubscribePacketIdentifier );

    if( mqttStatus != MQTTSuccess ) {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %s.", MQTT_Status_strerror( mqttStatus ) ) );
        returnStatus = EXIT_FAILURE;
    } else {
        LogInfo( ( "SUBSCRIBE sent for topic %s to broker (packetID = %d).",subscribe_info->pTopicFilter, globalSubscribePacketIdentifier) );
    }

    return returnStatus;
}

static int unsubscribeFromTopic( MQTTContext_t * pMqttContext, MQTTSubscribeInfo_t *unsubscribe_info)
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;

    assert( pMqttContext != NULL );

    /* Start with everything at 0. */
    memset( pGlobalSubscriptionList, 0x00, sizeof( pGlobalSubscriptionList ) );

    /* This example subscribes to and unsubscribes from only one topic and uses QOS1. */
    pGlobalSubscriptionList[ 0 ].qos               = unsubscribe_info->qos;
    pGlobalSubscriptionList[ 0 ].pTopicFilter      = unsubscribe_info->pTopicFilter;
    pGlobalSubscriptionList[ 0 ].topicFilterLength = unsubscribe_info->topicFilterLength;

    /* Generate packet identifier for the UNSUBSCRIBE packet. */
    globalUnsubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

    /* Send UNSUBSCRIBE packet. */
    mqttStatus = MQTT_Unsubscribe( pMqttContext, pGlobalSubscriptionList, sizeof( pGlobalSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ), globalUnsubscribePacketIdentifier );

    if( mqttStatus != MQTTSuccess ) {
        LogError( ( "Failed to send UNSUBSCRIBE packet to broker with error = %s.", MQTT_Status_strerror( mqttStatus ) ) );
        returnStatus = EXIT_FAILURE;
    } else {
        LogInfo( ( "UNSUBSCRIBE sent for topic %.*s to broker.", pGlobalSubscriptionList[0].topicFilterLength, pGlobalSubscriptionList[0].pTopicFilter ));
    }

    return returnStatus;
}

static int publishToTopic( MQTTContext_t * pMqttContext, PublishPackets_t * pPublish)
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    uint8_t publishIndex = MAX_OUTGOING_PUBLISHES;

    assert( pMqttContext != NULL );

    /* Get the next free index for the outgoing publish. All QoS1 outgoing
     * publishes are stored until a PUBACK is received. These messages are
     * stored for supporting a resend if a network connection is broken before
     * receiving a PUBACK. */
    returnStatus = getNextFreeIndexForOutgoingPublishes( &publishIndex );

    if( returnStatus == EXIT_FAILURE )
    {
        LogError( ( "Unable to find a free spot for outgoing PUBLISH message." ) );
    }
    else
    {
        /* This example publishes to only one topic and uses QOS1. */
        outgoingPublishPackets[ publishIndex ].pubInfo.qos             = pPublish->pubInfo.qos;
        outgoingPublishPackets[ publishIndex ].pubInfo.pTopicName      = pPublish->pubInfo.pTopicName;
        outgoingPublishPackets[ publishIndex ].pubInfo.topicNameLength = pPublish->pubInfo.topicNameLength;
        outgoingPublishPackets[ publishIndex ].pubInfo.pPayload        = pPublish->pubInfo.pPayload;
        outgoingPublishPackets[ publishIndex ].pubInfo.payloadLength   = pPublish->pubInfo.payloadLength;

        /* Get a new packet id. */
        outgoingPublishPackets[ publishIndex ].packetId = MQTT_GetPacketId( pMqttContext );

        /* Send PUBLISH packet. */
        mqttStatus = MQTT_Publish( pMqttContext, &outgoingPublishPackets[ publishIndex ].pubInfo, outgoingPublishPackets[ publishIndex ].packetId );

        if( mqttStatus != MQTTSuccess ) {
            LogError( ( "Failed to send PUBLISH packet to broker with error = %s.", MQTT_Status_strerror( mqttStatus ) ) );
            cleanupOutgoingPublishAt( publishIndex );
            returnStatus = EXIT_FAILURE;
        } else  {
            if (outgoingPublishPackets[publishIndex].pubInfo.qos == MQTTQoS0){
                cleanupOutgoingPublishAt( publishIndex );
                LogInfo( ( "PUBLISH Successful MQTTQoS0(cleanupOutgoingPublishAt)") );
            } else {
                LogInfo( ( "PUBLISH Successful MQTTQoS = %d", outgoingPublishPackets[publishIndex].pubInfo.qos) );
            }
            LogDebug( ( "PUBLISH sent for topic %.*s to broker with packet ID %u.", pPublish->pubInfo.topicNameLength, pPublish->pubInfo.pTopicName, outgoingPublishPackets[ publishIndex ].packetId ) );
        }
    }

    return returnStatus;
}

static int initializeMqtt( MQTTContext_t * pMqttContext, NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network. Network context is SSL context for OpenSSL.*/
    transport.pNetworkContext = pNetworkContext;
    transport.send = aws_ada_tls_send;
    transport.recv = aws_ada_tls_recv;

    /* Fill the values for network buffer. */
    networkBuffer.rx_pBuffer = g_mqtt_network_rx_buffer;
    networkBuffer.rx_size    = NETWORK_RX_BUFFER_SIZE;
    networkBuffer.tx_pBuffer = g_mqtt_network_tx_buffer;
    networkBuffer.tx_size    = NETWORK_TX_BUFFER_SIZE;

    /* Initialize MQTT library. */
    mqttStatus = MQTT_Init( pMqttContext, &transport, Clock_GetTimeMs, eventCallback, &networkBuffer );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
    }

    return returnStatus;
}

static int mqtt_evt_msg_process(void)
{
#define MQTT_RECV_EVT_TIMEOUT_MS       (20)
    mqtt_evt_t mqtt_evt = { 0 };
    int ret = 0;

    ret = mqtt_evt_msg_recv((void *)&mqtt_evt, MQTT_RECV_EVT_TIMEOUT_MS);
    if (ret == OS_OK)
    {
        switch (mqtt_evt.evt_id)
        {
            case MQTT_CLI_EVT_SUBSCRIBE :
                ret = -1;
                LogError( ("RECV_mqtt_subscribe EXIT_FAILURE msg.") );
                break;

            case MQTT_CLI_EVT_UNSUBSCRIBE:
                ret = -2;
                LogError( ("RECV_mqtt_unsubscribe EXIT_FAILURE msg.") );
                break;

            case MQTT_CLI_EVT_PUBLISH :
                ret = -3;
                LogError( ("RECV_mqtt_publish EXIT_FAILURE msg.") );
                break;

            case MQTT_CLI_EVT_CONN :
                mqtt_auto_reconnect = true;
                LogInfo( ("RECV_mqtt_connect msg.") );
                break;

            case MQTT_CLI_EVT_DISCONN :
                ret = -4;
                mqtt_auto_reconnect = false;
                LogInfo( ("RECV_mqtt_disconnect msg.") );
                break;
                
            default:
                break;
        }
    } else {
        ret = 0; 
    }

    return ret;
}

//消息订阅、发布 循环
static int subscribePublishLoop_v2( MQTTContext_t * pMqttContext )
{
#define _MQTT_PROCESS_LOOP_TIMEOUT_MS  (30)

    int ret = 0;
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    static uint32_t keepalive_timeout_cnt = 0;

    while(1)
    {
        if ((returnStatus == EXIT_SUCCESS) && (0 == mqtt_evt_msg_process()))
        {
            /* Process Incoming UNSUBACK packet from the broker. */
            mqttStatus = MQTT_ProcessLoop( pMqttContext, _MQTT_PROCESS_LOOP_TIMEOUT_MS );
            switch( mqttStatus )
            {
                case MQTTSuccess:
                    break;
                case MQTTKeepAliveTimeout:
                    LogError( ( "MQTT KeepAlive-Timeout(count=%d)!!!", keepalive_timeout_cnt++) );
                    break;
                case MQTTBadParameter:
                case MQTTNoMemory:
                case MQTTSendFailed:
                case MQTTRecvFailed:
                case MQTTBadResponse:
                case MQTTServerRefused:
                case MQTTNoDataAvailable:
                case MQTTIllegalState:
                case MQTTStateCollision:
                default:
                    returnStatus = EXIT_FAILURE;
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
                    break;
            }
        }
        else
        {
            LogError( ( "Maybe mqtt_evt execute error or RECV_mqtt_disconnect !!!") );
            break;
        }
    }

    /* Send an MQTT Disconnect packet over the already connected TCP socket.
    * There is no corresponding response for the disconnect packet. After sending disconnect, client must close the network connection. */
    LogInfo( ( "Disconnecting the MQTT connection with %.*s.", strlen(mqtt_cli_cfg->hostname), mqtt_cli_cfg->hostname ) );
    
    if ( mqtt_cli_cfg->disconnected_cb ) {
        mqtt_cli_cfg->disconnected_cb();
    }
    
    if( returnStatus == EXIT_FAILURE )
    {
        /* Returned status is not used to update the local status as there were failures in demo execution. */
        disconnectMqttSession( pMqttContext );
    }
    else
    {
        returnStatus = disconnectMqttSession( pMqttContext );
    }

    /* Reset global SUBACK status variable after completion of subscription request cycle. */
    globalSubAckStatus = MQTTSubAckFailure;

    return returnStatus;
}

/*-----------------------------------------------------------*/
static MQTTContext_t    g_mqttContext = { 0 };
static NetworkContext_t g_networkContext = { 0 };
static uint8_t g_mqtt_connected_callback_excuse_flag = 0;
int mqtt_evt_queue_reset(void);

void aws_demo_main(void *argv )
{
    int returnStatus = EXIT_SUCCESS;
    bool clientSessionPresent = false, brokerSessionPresent = false;

    ( void ) argv;
    mqtt_evt_t mqtt_evt = { 0 };

    /* Seed pseudo random number generator with nanoseconds. */
    srand(OS_GetTicks());

    memset(&g_mqttContext, 0, sizeof(MQTTContext_t));
    memset(&g_networkContext, 0, sizeof(NetworkContext_t));

    /* Initialize MQTT library. Initialization of the MQTT library needs to be done only once in this demo. */
    returnStatus = initializeMqtt( &g_mqttContext, &g_networkContext );

    if( returnStatus == EXIT_SUCCESS )
    {
        for( ; ; )
        {
            if (netdev_got_ip() && mqtt_auto_reconnect)  {
                /* (wifi connected  & got ip) */
                mqtt_evt_queue_reset();// cleanup all events
            } else {
                Clock_SleepMs(80);
                mqtt_evt_msg_process();
                continue;
            }

            /* TCP/TLS connect, mqtt connect (with backoff retry) */
            returnStatus = connectToServerWithBackoffRetries( &g_networkContext, &g_mqttContext, &clientSessionPresent, &brokerSessionPresent );

            if( returnStatus == EXIT_FAILURE )
            {
                LogError( ( "Failed to connect to MQTT broker %s.", mqtt_cli_cfg->hostname ) );
            }
            else
            {
                clientSessionPresent = false; 
                brokerSessionPresent = false;
                cleanupOutgoingPublishes();

                g_mqtt_connected_callback_excuse_flag = 1;
                mqtt_cli_cfg->is_connected = 1;
                returnStatus = subscribePublishLoop_v2( &g_mqttContext );

                aws_ada_tls_disconn( &g_networkContext );
                g_mqtt_connected_callback_excuse_flag = 0;
                mqtt_cli_cfg->is_connected = 0;
            }

            LogInfo( ( "Short delay before starting the next iteration....\r\n" ) );
            Clock_SleepMs(1000 * MQTT_SUBPUB_LOOP_DELAY_SECONDS);
        }
    }
}

/*-----------------------------------------------------------*/
int mqtt_evt_msg_recv(void *mqtt_evt, uint32_t timeout)
{
    return OS_QueueReceive(&mqtt_evt_queue, mqtt_evt, timeout);
}

int mqtt_evt_queue_reset(void)
{
    xQueueReset(mqtt_evt_queue.handle);    
    return OS_OK;
}

int __mqtt_cli_subscribe(const char* topic_filter, int qos)
{
    int ret = -1;
    MQTTSubscribeInfo_t subscribe_info;
    memset(&subscribe_info, 0, sizeof(MQTTSubscribeInfo_t));
    static mqtt_evt_t _evt = { 0 };
    int returnStatus = EXIT_SUCCESS;

    if (mqtt_cli_cfg->is_connected == 0) {
        LOG(LOG_LVL_INFO, "mqtt client is not connected!! __mqtt_cli_subscribe() topic:[%s]\r\n", topic_filter);
        return -1;
    }

    OS_MutexLock(&g_mqtt_api_lock, OS_WAIT_FOREVER);
    {
        subscribe_info.qos               = (MQTTQoS_t)qos;
        subscribe_info.pTopicFilter      = topic_filter;
        subscribe_info.topicFilterLength = strlen(topic_filter);

        LOG(LOG_LVL_INFO, "__mqtt_cli_subscribe() topic:[%s]\r\n", topic_filter);
        returnStatus = subscribeToTopic( &g_mqttContext, &subscribe_info );

        if (returnStatus != EXIT_SUCCESS) {
            _evt.evt_id  = MQTT_CLI_EVT_SUBSCRIBE;
            _evt.len     = 0;
            _evt.buffer  = NULL;
            OS_QueueSend(&mqtt_evt_queue, &_evt, 10000);
            ret = -1;
        } else {
            ret = 0;
        }
    }
    OS_MutexUnlock(&g_mqtt_api_lock);
    return ret;
}

int __mqtt_cli_unsubscribe(const char* topic_filter)
{
    int ret = -1;
    MQTTSubscribeInfo_t unsubscribe_info;
    memset(&unsubscribe_info, 0, sizeof(MQTTSubscribeInfo_t));
    static mqtt_evt_t _evt = { 0 };
    int returnStatus = EXIT_SUCCESS;

    if (mqtt_cli_cfg->is_connected == 0) {
        LOG(LOG_LVL_INFO, "mqtt client is not connected!! __mqtt_cli_unsubscribe() topic:[%s]\r\n", topic_filter);
        return -1;
    }

    OS_MutexLock(&g_mqtt_api_lock, OS_WAIT_FOREVER);
    {
        unsubscribe_info.qos               = MQTTQoS0;
        unsubscribe_info.pTopicFilter      = topic_filter;
        unsubscribe_info.topicFilterLength = strlen(topic_filter);

        LOG(LOG_LVL_INFO, "__mqtt_cli_unsubscribe() topic:[%s]\r\n", topic_filter);
        returnStatus = unsubscribeFromTopic( &g_mqttContext, &unsubscribe_info );

        if (returnStatus != EXIT_SUCCESS) {
            _evt.evt_id  = MQTT_CLI_EVT_UNSUBSCRIBE;
            _evt.len     = 0;
            _evt.buffer  = NULL;
            OS_QueueSend(&mqtt_evt_queue, &_evt, 10000);
            ret = -1;
        } else {
            ret = 0;
        }
    }
    OS_MutexUnlock(&g_mqtt_api_lock);
    return ret;
}

int __mqtt_cli_publish(const char* topic_filter, const char *data, int datalen, int qos, int retain)
{
    int ret = -1;
    PublishPackets_t publish_packets = { 0 };
    static mqtt_evt_t _evt = { 0 };
    int returnStatus = EXIT_SUCCESS;

    if (mqtt_cli_cfg->is_connected == 0) {
        LOG(LOG_LVL_INFO, "mqtt client is not connected!! __mqtt_cli_publish() topic:[%s]\r\n", topic_filter);
        return -1;
    }

    OS_MutexLock(&g_mqtt_api_lock, OS_WAIT_FOREVER);
    {
        publish_packets.pubInfo.qos             = (MQTTQoS_t)qos;
        publish_packets.pubInfo.retain          = retain;
        publish_packets.pubInfo.dup             = 0;
        publish_packets.pubInfo.pTopicName      = topic_filter;
        publish_packets.pubInfo.topicNameLength = strlen(topic_filter);
        publish_packets.pubInfo.pPayload        = data;
        publish_packets.pubInfo.payloadLength   = strlen(data);

        returnStatus = publishToTopic( &g_mqttContext, &publish_packets);
        // LOG(LOG_LVL_INFO, "__mqtt_cli_publish() topic:[%s], qos=%d, retain=%d, playload:[%s]\r\n", topic_filter, qos, retain, data);
        // LOG(LOG_LVL_INFO, "__mqtt_cli_publish() topic:[%s], qos=%d, retain=%d returnStatus=%d\r\n", topic_filter, qos, retain, returnStatus);

        if (returnStatus != EXIT_SUCCESS) {
            _evt.evt_id  = MQTT_CLI_EVT_PUBLISH;
            _evt.len     = 0;
            _evt.buffer  = NULL;
            OS_QueueSend(&mqtt_evt_queue, &_evt, 10000);
            ret = -1;
        } else {
            ret = 0;
        }
    }
    OS_MutexUnlock(&g_mqtt_api_lock);
    return ret;
}

void __mqtt_cli_conn(void)
{
    mqtt_evt_t _evt = { 0 };

    OS_MutexLock(&g_mqtt_api_lock, OS_WAIT_FOREVER);
    {
        _evt.evt_id  = MQTT_CLI_EVT_CONN;
        _evt.len     = 0;
        _evt.buffer  = NULL;
        OS_QueueSend(&mqtt_evt_queue, &_evt, 10000);
    }
    OS_MutexUnlock(&g_mqtt_api_lock);
}

void __mqtt_cli_disconn(void)
{
    mqtt_evt_t _evt = { 0 };

    OS_MutexLock(&g_mqtt_api_lock, OS_WAIT_FOREVER);
    {
        _evt.evt_id  = MQTT_CLI_EVT_DISCONN;
        _evt.len     = 0;
        _evt.buffer  = NULL;
        OS_QueueSend(&mqtt_evt_queue, &_evt, 10000);
    }
    OS_MutexUnlock(&g_mqtt_api_lock);

    LOG(LOG_LVL_INFO, "__mqtt_cli_disconn()\r\n");
}

static void _mqtt2_task_entry(void *params)
{
    while(1)
    {
        if (g_mqtt_connected_callback_excuse_flag == 1) {
            g_mqtt_connected_callback_excuse_flag = 0;

            if (mqtt_cli_cfg->connected_cb) {
                mqtt_cli_cfg->connected_cb();
            }
        }
        OS_MsDelay(500);
    }
}

void print_mqtt_client_info(mqtt_client_cfg_t *cli)
{
    LOG(LOG_LVL_INFO, "MQTT hostname:[%s] port:[%d]\r\n", cli->hostname, cli->port);
    LOG(LOG_LVL_INFO, "MQTT keepalive:%d\r\n", cli->keepalive);
    LOG(LOG_LVL_INFO, "MQTT client id:%s\r\n", cli->client_id == NULL ? "NULL" : cli->client_id);
    LOG(LOG_LVL_INFO, "MQTT username:%s\r\n",  cli->username == NULL ? "NULL" : cli->username);
    LOG(LOG_LVL_INFO, "MQTT password:%s\r\n",  cli->password == NULL ? "NULL" : cli->password);
}

void creat_mqtt_task(mqtt_client_cfg_t *mqtt_client_cfg)
{
    mqtt_cli_cfg = mqtt_client_cfg;
    print_mqtt_client_info(mqtt_cli_cfg);

    if(OS_OK != OS_QueueCreate(&mqtt_evt_queue, MQTT_EVT_MSG_QUEUE_SIZE, sizeof(mqtt_evt_t))) {
        LOG(LOG_LVL_ERROR, " QueueCreate mqtt_evt_queue failed!!!\r\n");
    }

    if(OS_OK != OS_ThreadCreate(&g_mqtt_thread, "mqtt_cli", aws_demo_main, NULL, OS_PRIORITY_NORMAL, MQTT_TASK_STACK_SIZE)) {
        LOG(LOG_LVL_ERROR, " OS_ThreadCreate g_mqtt_thread failed!!!\r\n");
    }

    if(OS_OK != OS_ThreadCreate(&g_mqtt2_thread, "mqtt2_cli", _mqtt2_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, MQTT2_TASK_STACK_SIZE)) {
        LOG(LOG_LVL_ERROR, " OS_ThreadCreate g_mqtt_thread failed!!!\r\n");
    }

    if (OS_OK != OS_MutexCreate(&g_mqtt_api_lock)) {
        LOG(LOG_LVL_ERROR, " OS_MutexCreate g_mqtt_api_lock failed!!!\r\n");
    }
}
