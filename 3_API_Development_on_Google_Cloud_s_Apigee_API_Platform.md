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
