# Examples

## SATOSA Context object

Context object properties

````
'_path', 
'request', 
'request_uri', 
'request_method', 
'qs_params', 
'server', 
'http_headers', 
'cookie', 
'request_authorization', 
'target_backend', 
'target_frontend', 
'target_micro_service', 
'internal_data', 
'state'
````

Context object representation

````
{
  "_path": "Saml2/disco",
  "request": null,
  "request_uri": "/Saml2/disco?entityID=wallet",
  "request_method": "GET",
  "qs_params": {
    "entityID": "wallet"
  },
  "server": {
    "SERVER_PROTOCOL": "HTTP/1.1",
    "SERVER_NAME": "that-machine",
    "SERVER_PORT": "10000"
  },
  "http_headers": {
    "REMOTE_ADDR": "127.0.0.1",
    "REMOTE_PORT": "7824",
    "HTTP_HOST": "localhost:10000",
    "HTTP_USER_AGENT": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "HTTP_ACCEPT_LANGUAGE": "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3",
    "HTTP_ACCEPT_ENCODING": "gzip, deflate, br",
    "HTTP_CONNECTION": "keep-alive",
    "HTTP_REFERER": "https://localhost:9999/",
    "HTTP_COOKIE": " csrftoken=Yb7Dled4redGlyel4EkbTjbVnODbISaZKexcFELrxtHG633aWmytVALWurMbxVXG; saml_session=yagufew9tt3feqj6z60z6e9i14imtpmr; SATOSA_STATE=_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AQ_A4xdACEbCCMSnyX365kSn_2E5_fa0KE-LmmTyjfLosClnKEuMvfIVutti0WZwQAKgUJTc7oLHFmKDHHU55WeeCu34Y6kiZWmOQFX-uUp1LFJkAvf2KpEk9Hm01KDObPJW7f59BXGU1lm9HxXJeMIde1uXQ9-RkUmhkDnOj-9yfKj95BCEoqewEaU3hESBMyzg5Sq7bGJ6Y3JOsAjMpsS-4EBqwunH4CWQYiqibH-QQoCJhs-cRQvL0Wbmgdfg3FPgYuRgR7R_836zpL3srcCHFtQC1oi7TikHZMzhLw9eqGmiEkHrsy0KBIxsY5KB9D5h402Vm26ZIcaOBnubeRH_6afUFrx0Ek33BsiXXY_Obj--9bKY-D2CVr8Dt_KX0s1YfDA4Yoi9zv-iEFiFtXPFi32oA5sdykj2UvWZbqs0fKIbLhwpQviA7N7xy0Ji2V1a4Lnq4iWYztBtF5MYYuxqYHIJun0qz4vJtuvw7s0F8x1sIgXzljQBMkWLCdj7Fgn4ervljP46xG-Hk4-r6XC1oXuqVHx8Q6o61SD7qu2YJfl-I1twb0XbQPFAtnTtx3XvSweZHoIujFE3mGWmmzH7FbIAv8NR6t2jKFSLLf7VyvHUYv8LTrjaoMRawEVwAGWYlckOXWh1qMJRbK4TVXdwIf46u5tXrmLkrAnnedtI5vDV_8i6mVtEsAULhoCGchUYbcUVfurVpkpRW1v4-x20OnaYVAQQH5ckxo6lPz7NEUzbN7IC-JiAKFCI3jDRqN10rvh-tIjcaCsNjNEFkJlWVjfoTrwIUo2qrSSJ9NGzUUaSKwqMUq4AtGz14WKX5C_lcVntKUvVHFeWOfmcGAD5HQBLPX8fn4SQCb3kcFpiDaZnSFLNpwEEiiyFa5pioJRWuZh1U8mAVQ2Mq8MgmrfUgUfwyXKxLjlA4Mn4eWAG1_cjiQSxuvJbvTJgZ9VO1T5f5KoR-I1VbtK8HIm9hZmH91MMamJZvGsyD4ecNeVJTq0Ee8aza1khgmF_Mc_3vtZVaQ5dKTkrf7A3JM5O7e-_8grdetAo3PZZ1dUCnzj3NvPUfioilWW2OZ6QPmgOxL6EqPwecLyOyqY5kbUa9dayhUeyh-H6OpIyOpYY4__XrJPvoUNokrYoWbTPWoqem12wiwiA80xkOlSzEZchnVHGX3r042Y3NR73EIu630_Murt_2TYAsSkN0FEcOp4E9Z4AKm07OyS-v92AAGoB8AIAADwJGT8scRn-wIAAAAABFla; SATOSA_STATE_LEGACY=_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AQ_A4xdACEbCCMSnyX365kSn_2E5_fa0KE-LmmTyjfLosClnKEuMvfIVutti0WZwQAKgUJTc7oLHFmKDHHU55WeeCu34Y6kiZWmOQFX-uUp1LFJkAvf2KpEk9Hm01KDObPJW7f59BXGU1lm9HxXJeMIde1uXQ9-RkUmhkDnOj-9yfKj95BCEoqewEaU3hESBMyzg5Sq7bGJ6Y3JOsAjMpsS-4EBqwunH4CWQYiqibH-QQoCJhs-cRQvL0Wbmgdfg3FPgYuRgR7R_836zpL3srcCHFtQC1oi7TikHZMzhLw9eqGmiEkHrsy0KBIxsY5KB9D5h402Vm26ZIcaOBnubeRH_6afUFrx0Ek33BsiXXY_Obj--9bKY-D2CVr8Dt_KX0s1YfDA4Yoi9zv-iEFiFtXPFi32oA5sdykj2UvWZbqs0fKIbLhwpQviA7N7xy0Ji2V1a4Lnq4iWYztBtF5MYYuxqYHIJun0qz4vJtuvw7s0F8x1sIgXzljQBMkWLCdj7Fgn4ervljP46xG-Hk4-r6XC1oXuqVHx8Q6o61SD7qu2YJfl-I1twb0XbQPFAtnTtx3XvSweZHoIujFE3mGWmmzH7FbIAv8NR6t2jKFSLLf7VyvHUYv8LTrjaoMRawEVwAGWYlckOXWh1qMJRbK4TVXdwIf46u5tXrmLkrAnnedtI5vDV_8i6mVtEsAULhoCGchUYbcUVfurVpkpRW1v4-x20OnaYVAQQH5ckxo6lPz7NEUzbN7IC-JiAKFCI3jDRqN10rvh-tIjcaCsNjNEFkJlWVjfoTrwIUo2qrSSJ9NGzUUaSKwqMUq4AtGz14WKX5C_lcVntKUvVHFeWOfmcGAD5HQBLPX8fn4SQCb3kcFpiDaZnSFLNpwEEiiyFa5pioJRWuZh1U8mAVQ2Mq8MgmrfUgUfwyXKxLjlA4Mn4eWAG1_cjiQSxuvJbvTJgZ9VO1T5f5KoR-I1VbtK8HIm9hZmH91MMamJZvGsyD4ecNeVJTq0Ee8aza1khgmF_Mc_3vtZVaQ5dKTkrf7A3JM5O7e-_8grdetAo3PZZ1dUCnzj3NvPUfioilWW2OZ6QPmgOxL6EqPwecLyOyqY5kbUa9dayhUeyh-H6OpIyOpYY4__XrJPvoUNokrYoWbTPWoqem12wiwiA80xkOlSzEZchnVHGX3r042Y3NR73EIu630_Murt_2TYAsSkN0FEcOp4E9Z4AKm07OyS-v92AAGoB8AIAADwJGT8scRn-wIAAAAABFla",
    "HTTP_UPGRADE_INSECURE_REQUESTS": "1",
    "HTTP_SEC_FETCH_DEST": "document",
    "HTTP_SEC_FETCH_MODE": "navigate",
    "HTTP_SEC_FETCH_SITE": "same-site",
    "HTTP_SEC_FETCH_USER": "?1"
  },
  "cookie": " csrftoken=Yb7Dled4redGlyel4EkbTjbVnODbISaZKexcFELrxtHG633aWmytVALWurMbxVXG; saml_session=yagufew9tt3feqj6z60z6e9i14imtpmr; SATOSA_STATE=_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AQ_A4xdACEbCCMSnyX365kSn_2E5_fa0KE-LmmTyjfLosClnKEuMvfIVutti0WZwQAKgUJTc7oLHFmKDHHU55WeeCu34Y6kiZWmOQFX-uUp1LFJkAvf2KpEk9Hm01KDObPJW7f59BXGU1lm9HxXJeMIde1uXQ9-RkUmhkDnOj-9yfKj95BCEoqewEaU3hESBMyzg5Sq7bGJ6Y3JOsAjMpsS-4EBqwunH4CWQYiqibH-QQoCJhs-cRQvL0Wbmgdfg3FPgYuRgR7R_836zpL3srcCHFtQC1oi7TikHZMzhLw9eqGmiEkHrsy0KBIxsY5KB9D5h402Vm26ZIcaOBnubeRH_6afUFrx0Ek33BsiXXY_Obj--9bKY-D2CVr8Dt_KX0s1YfDA4Yoi9zv-iEFiFtXPFi32oA5sdykj2UvWZbqs0fKIbLhwpQviA7N7xy0Ji2V1a4Lnq4iWYztBtF5MYYuxqYHIJun0qz4vJtuvw7s0F8x1sIgXzljQBMkWLCdj7Fgn4ervljP46xG-Hk4-r6XC1oXuqVHx8Q6o61SD7qu2YJfl-I1twb0XbQPFAtnTtx3XvSweZHoIujFE3mGWmmzH7FbIAv8NR6t2jKFSLLf7VyvHUYv8LTrjaoMRawEVwAGWYlckOXWh1qMJRbK4TVXdwIf46u5tXrmLkrAnnedtI5vDV_8i6mVtEsAULhoCGchUYbcUVfurVpkpRW1v4-x20OnaYVAQQH5ckxo6lPz7NEUzbN7IC-JiAKFCI3jDRqN10rvh-tIjcaCsNjNEFkJlWVjfoTrwIUo2qrSSJ9NGzUUaSKwqMUq4AtGz14WKX5C_lcVntKUvVHFeWOfmcGAD5HQBLPX8fn4SQCb3kcFpiDaZnSFLNpwEEiiyFa5pioJRWuZh1U8mAVQ2Mq8MgmrfUgUfwyXKxLjlA4Mn4eWAG1_cjiQSxuvJbvTJgZ9VO1T5f5KoR-I1VbtK8HIm9hZmH91MMamJZvGsyD4ecNeVJTq0Ee8aza1khgmF_Mc_3vtZVaQ5dKTkrf7A3JM5O7e-_8grdetAo3PZZ1dUCnzj3NvPUfioilWW2OZ6QPmgOxL6EqPwecLyOyqY5kbUa9dayhUeyh-H6OpIyOpYY4__XrJPvoUNokrYoWbTPWoqem12wiwiA80xkOlSzEZchnVHGX3r042Y3NR73EIu630_Murt_2TYAsSkN0FEcOp4E9Z4AKm07OyS-v92AAGoB8AIAADwJGT8scRn-wIAAAAABFla; SATOSA_STATE_LEGACY=_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AQ_A4xdACEbCCMSnyX365kSn_2E5_fa0KE-LmmTyjfLosClnKEuMvfIVutti0WZwQAKgUJTc7oLHFmKDHHU55WeeCu34Y6kiZWmOQFX-uUp1LFJkAvf2KpEk9Hm01KDObPJW7f59BXGU1lm9HxXJeMIde1uXQ9-RkUmhkDnOj-9yfKj95BCEoqewEaU3hESBMyzg5Sq7bGJ6Y3JOsAjMpsS-4EBqwunH4CWQYiqibH-QQoCJhs-cRQvL0Wbmgdfg3FPgYuRgR7R_836zpL3srcCHFtQC1oi7TikHZMzhLw9eqGmiEkHrsy0KBIxsY5KB9D5h402Vm26ZIcaOBnubeRH_6afUFrx0Ek33BsiXXY_Obj--9bKY-D2CVr8Dt_KX0s1YfDA4Yoi9zv-iEFiFtXPFi32oA5sdykj2UvWZbqs0fKIbLhwpQviA7N7xy0Ji2V1a4Lnq4iWYztBtF5MYYuxqYHIJun0qz4vJtuvw7s0F8x1sIgXzljQBMkWLCdj7Fgn4ervljP46xG-Hk4-r6XC1oXuqVHx8Q6o61SD7qu2YJfl-I1twb0XbQPFAtnTtx3XvSweZHoIujFE3mGWmmzH7FbIAv8NR6t2jKFSLLf7VyvHUYv8LTrjaoMRawEVwAGWYlckOXWh1qMJRbK4TVXdwIf46u5tXrmLkrAnnedtI5vDV_8i6mVtEsAULhoCGchUYbcUVfurVpkpRW1v4-x20OnaYVAQQH5ckxo6lPz7NEUzbN7IC-JiAKFCI3jDRqN10rvh-tIjcaCsNjNEFkJlWVjfoTrwIUo2qrSSJ9NGzUUaSKwqMUq4AtGz14WKX5C_lcVntKUvVHFeWOfmcGAD5HQBLPX8fn4SQCb3kcFpiDaZnSFLNpwEEiiyFa5pioJRWuZh1U8mAVQ2Mq8MgmrfUgUfwyXKxLjlA4Mn4eWAG1_cjiQSxuvJbvTJgZ9VO1T5f5KoR-I1VbtK8HIm9hZmH91MMamJZvGsyD4ecNeVJTq0Ee8aza1khgmF_Mc_3vtZVaQ5dKTkrf7A3JM5O7e-_8grdetAo3PZZ1dUCnzj3NvPUfioilWW2OZ6QPmgOxL6EqPwecLyOyqY5kbUa9dayhUeyh-H6OpIyOpYY4__XrJPvoUNokrYoWbTPWoqem12wiwiA80xkOlSzEZchnVHGX3r042Y3NR73EIu630_Murt_2TYAsSkN0FEcOp4E9Z4AKm07OyS-v92AAGoB8AIAADwJGT8scRn-wIAAAAABFla",
  "request_authorization": "",
  "target_backend": "OpenID4VP",
  "target_frontend": "Saml2IDP",
  "target_micro_service": "DiscoToTargetIssuer",
  "internal_data": {
    "target_entity_id": "wallet"
  },
  "state": {
    "SESSION_ID": "urn:uuid:6f7a1492-8c5a-4020-be36-572b91e83e2a",
    "Saml2IDP": {
      "resp_args": {
        "in_response_to": "id-yGMJfNfHuAJf2nf93",
        "sp_entity_id": "http://localhost:8000/saml2/metadata/",
        "name_id_policy": "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" />",
        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        "destination": "http://localhost:8000/saml2/acs/"
      },
      "relay_state": "/saml2/echo_attributes"
    },
    "SATOSA_BASE": {
      "requester": "http://localhost:8000/saml2/metadata/"
    },
    "DiscoToTargetIssuer": {
      "target_frontend": "Saml2IDP",
      "internal_data": {
        "auth_info": {
          "auth_class_ref": null,
          "timestamp": null,
          "issuer": null,
          "authority": null
        },
        "requester": "http://localhost:8000/saml2/metadata/",
        "requester_name": [
          {
            "text": "http://localhost:8000/saml2/metadata/",
            "lang": "en"
          }
        ],
        "subject_id": null,
        "subject_type": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "attributes": [
          "schachomeorganizationtype",
          "schachomeorganization",
          "surname",
          "mail",
          "dateOfBirth",
          "schacpersonaluniquecode",
          "expirationDate",
          "displayname",
          "givenname",
          "gender",
          "edupersontargetedid",
          "placeOfBirth",
          "companyName",
          "ivaCode",
          "edupersonscopedaffiliation",
          "fiscalnumber",
          "name",
          "spidcode",
          "registeredOffice",
          "email",
          "mobilePhone",
          "edupersonentilement",
          "digitalAddress",
          "familyname",
          "address",
          "edupersonprincipalname",
          "schacpersonaluniqueid",
          "countyOfBirth",
          "idCard"
        ]
      }
    },
    "ROUTER": "Saml2IDP",
    "force_authn": "true"
  }
}
````
