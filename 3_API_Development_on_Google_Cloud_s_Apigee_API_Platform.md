# Topics

- API mediation
- Traffic management
- API publishing
- Analytics
- Apigee offline development
- Apigee deployment options

# API mediation

- Set Content-Type header
- JSONToXML and XMLToJSON policies (JSON: Javascript Object Notation, XML: eXtensible Markup Language)
  - StripLevels
  - RecognizeNumber
  - RecognizeBoolean
- XSL Transform policy (eXtensible Stylesheet Language)
- MessageValidation policy validates (Content-Type must be set, XSD and WSDL files must be stored in the proxy for validation to occur):
  - XML against XSD stored in proxy resources (eXtensible Service Description)
  - SOAP against WSDL stored in proxy resources (WSDL: Web Service Description Language)
  - Confirm that JSON or SOAP is well-formed (SOAP: Simple Object Access Protocol)
- SOAP to REST Wizard

- Mediation pattern: Format conversion:

  - ExtractVariables

    - Header
    - URIPath
    - QueryParam
    - JSONPath
    - XPath

  - AssignMessage

    - AssignVariable
    - Set
    - Remove

  - Templates

- Mediation pattern: Orchestration

  - ServiceCallout policy

    - Request
    - Response
    - Timeout
    - HTTPTargetConnection
      - URL

  - Proxy chaining (in same org & env), can be used in TargetEndpoints and ServiceCallouts
    - LocalTargetConnection
      - Path
      - or
      - APIProxy and ProxyEndpoint

- Custom code policies

  - Javascript policy
    - IncludeURL
    - ResourceURL
  - JavaCallout policy
  - Python policy

- Shared Flow
- A method for sharing code inside proxies (just like proxy chaining)
- Single flow of reusable logic containing policies, policy conditions, and resources
- Cannot be invoked directly (shared flows live in the context of a hosting proxy flow)
- Hosted in an org and deployed to an env
- Can only be used by proxy or shared flow deployed to the same org/env
- FlowCallout policy

  - Call shared flow from a proxy or another shared flow
  - Shared flow must be deployed to an environment before proxy or shared flow using it can be deployed
  - FlowCallout
    - SharedFlowBundle
      - SharedFlow name

- Flow hooks

  - Attach shared flow for all proxies in an environment
    - Pre-proxy Flow Hook
    - Pre-target Flow Hook
    - Post-target Flow Hook
    - Post-proxy Flow Hook

- Fault Handling

  - FaultRules
    - FaultRules
    - FaultRules are evaluated from bottom to top in **ProxyEndpoint** (only part of a proxy that is evaluated in reverse order)
    - FaultRules are evaluated in normal order in **TargetEndpoint**
  - DefaultFaultRule

    - AlwaysEnforce
      - true: always runs after the fault rules
      - false: runs after the fault rules only if no matching fault rule was found

  - Faults are raised:

    - When **continueOnError = false** in policy
    - Non success response recieved from backend or service callout (success codes default to 1xx, 2xx, 3xx, can be overriden by **success.codes** property)
    - Using a RaiseFault policy

      - RaiseFault
        - FaultResponse

    - 404 Not Found
      - Bsest practice is to allow approved operations

- Extensions

  - Stores and manages service credentials
  - Retrieves tokens and manages token expiration
  - Builds and parses the API request and response

- Apigee components

  - Gateway
    - Router
    - Message Processor
  - Runtime Data Store
  - Analytics services
  - Management service (API)
  - Management UI
  - Developer Portal

- Rate Limiting with Spike Arrests and Quotas

  - Traffic spikes
    - SpikeArrest policy
      - Keeps track of when the last matching request was allowed
      - Does not use au counter
      - Solves a technical problem
      - Rejected traffic returns **429 Too Many Requests** status code
      - The variable "system.uuid" is unique for each message processor. This value can be specified in a response header if you want to be able to distinguish requests that are handled by different message processors.
      - SpikeArrest
        - Rate (10ps, 30pm)
        - Identifier ref = client_id
        - MessageWeight
        - UseEffectiveCount = true divides the specified rate accros MPs(Message processors). Default is false
  - Quotas

    - Quota policy

      - Solves a business problem
      - Uses a counter
      - Count is typically shared among all message processors
      - Quota is scoped to a single proxy and policy. Counters cannot be shared between proxies or policies
      - Combination of proxy, policy and identifiers uniquely identifies a quota counter
      - Rejected traffic returns **429 Too Many Requests** status code
      - Quota
        - Allow
        - Interval
        - TimeUnit
        - Indentifier
        - MessageWeight
        - Distributed
        - Synchronous
        - AsynchronousConfiguration
          - SyncIntervalInSeconds
          - SyncMessageCount
      - Quota can be set at the API Product level and accessed via variables created when an API key or token is verified (**verifyapikey.VK-VerifyKey.apiproduct.developer.quota.{limit, interval, timeunit}**)
      - Quota type:
        - default
        - calendar
        - flexi
        - rollingwindow

    - Reset Quota policy
      - ResetQuota
        - Quota
          - Identifier
            - Allow

- Caching

  - TTL (time-to-live)
  - L1 cache
    - in-memory
    - is checked first
  - L2 cache

    - stored in runtime data store
    - slower than L1 but much faster than network calls
    - MP populates L1 cache when entry is read from L2

  - L1 automatic caching (180s after access)

    - OAuth access tokens
    - Developers, Developers apps, API products
    - Custom attributes on the aforementioned

  - PopulateCache policy

    - adds an entry to the cache
    - PopulateCache
      - CacheResource
      - CacheKey
        - Prefix
        - KeyFragment
      - Scope (must be set if Cache prefix is not set)
        - Global: org\_\_env
        - Application: org**env**proxy
        - Exclusive: org**env**proxy\_\_endpoint
      - ExpirySettings
        - TimeoutInSec / ExpiryDate / TimeOfDay
      - Source

  - LookupCache policy

    - looks for an entry in a cache
    - cachehit variable is populated (true/false)
    - LookupCache
      - CacheResource
      - CacheKey
        - Prefix
        - KeyFragment
      - Scope (must be set if Cache prefix is not set)
        - Global: org\_\_env
        - Application: org**env**proxy
        - Exclusive: org**env**proxy\_\_endpoint
      - CacheLookupTimeoutInSeconds (default: 30s)
      - AssignTo

  - InvalidateCache policy

    - purge entries from a caches
    - InvalidateCache
      - CacheResource
      - CacheKey
        - KeyFragment
      - Scope (must be set if Cache prefix is not set)
        - Global: org\_\_env
        - Application: org**env**proxy
        - Exclusive: org**env**proxy\_\_endpoint
      - CacheContext
        - APIProxyName / ProxyName(endpoint) / TargetName
      - PurgeChildEntries

  - Response caching

    - ResponseCache policy

      - streamlines the process of caching HTTP responses
      - handle both the lookup and the population of the cache
      - is attached to exactly 2 places: a request flow (checks the cache) and a response flow (populates the cache)

      - ResponseCache
        - CacheResource
        - CacheKey
          - KeyFragment
        - ExpirySettings
          - TimeoutInSec / ExpiryDate / TimeOfDay
        - UseAcceptHeader
        - ExcludeErrorResponse
        - SkipCacheLookup
        - SkipCachePopulation
        - UseResponseCacheHeaders
          - If true caching-related headers in the response will be used with this precedence:
            1. Cache-Control s-max-age
            2. Cache-Control max-age
            3. Expires
          - If one of those headers is used, its expiration is compared to the _ExpirySettings_ value, and the lower expiration time is used

    - Response cache best practices:
      - Only cache GET requests
      - Think carefully about cache key fragments
      - Use unique user identifier as a key fragment
      - Use proxy.pathsuffix and specific query parameters as key fragments instead of entire URL

- API Publishing

  - API versionning
  - Developer Portals

- Logging

  - MessageLogging policy
    - continueOnError=true
    - in the PostClientFlow
    - MessageLogging
      - Syslog
        - Message
        - Host
        - Port
        - Protocol (TCP/UDP)
        - SSLInfo (if TCP)
          - Enabled

- Analytics

  - App analytics
  - Developer analytics
  - API analytics
  - StatisticsCollector policy
    - StatisticsCollector
      - Statistics
        - Statistic (name, ref, type)

- CI/CD
  - Maven plugins
    - apigee-deploy-maven-plugin
    - apigee-config-maven-plugin
  - CLI tool
    - apigeetool
  - Management API
    - CLI get_token
    - CLI acurl
