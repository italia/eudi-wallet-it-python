# SD-JWT Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Python.

This implementation is used to generate the examples in the IETF SD-JWT specification and it can also be used in other projects for implementing SD-JWT.

## Setup

To install this implementation, make sure that `python3` and `pip` (or `pip3`) are available on your system and run the following command:

```bash
# create a virtual environment to install the dependencies
python3 -m venv venv
source venv/bin/activate

# install the latest version from git
pip install git+https://github.com/openwallet-foundation-labs/sd-jwt-python.git
```

This will install the `sdjwt` python package and the `sd-jwt-generate` script.

If you want to access the scripts in a new shell, it is required to activate the virtual environment:

```bash
source venv/bin/activate
```

## sd-jwt-generate

The script `sd-jwt-generate` is useful for generating test cases, as they might be used for doing interoperability tests with other SD-JWT implementations, and for generating examples in the SD-JWT specification and other documents.

For both use cases, the script expects a JSON file with settings (`settings.yml`). Examples for these files can be found in the [tests/testcases](tests/testcases) and [examples](examples) directories.

Furthermore, the script expects, in its working directory, one subdirectory for each test case or example. In each such directory, there must be a file `specification.yml` with the test case or example specifications. Examples for these files can be found in the subdirectories of the [tests/testcases](tests/testcases) and [examples](examples) directories, respectively.

The script outputs the following files in each test case or example directory:
 * `sd_jwt_issuance.txt`: The issued SD-JWT. (*)
 * `sd_jwt_presentation.txt`: The presented SD-JWT. (*)
 * `disclosures.md`: The disclosures, formatted as markdown (only in 'example' mode).
 * `user_claims.json`: The user claims.
 * `sd_jwt_payload.json`: The payload of the SD-JWT.
 * `sd_jwt_jws_part.txt`: The serialized JWS component of the SD-JWT. (*)
 * `kb_jwt_payload.json`: The payload of the key binding JWT.
 * `kb_jwt_serialized.txt`: The serialized key binding JWT.
 * `verified_contents.json`: The verified contents of the SD-JWT.

(*) Note: When JWS JSON Serialization is used, the file extensions of these files are `.json` instead of `.txt`.

To run the script, enter the respective directory and execute `sd-jwt-generate`:

```bash
cd tests/testcases
sd-jwt-generate example
```

## specification.yml for Test Cases and Examples

The `specification.yml` file contains the test case or example specifications.
For examples, the file contains the 'input user data' (i.e., the payload that is
turned into an SD-JWT) and the holder disclosed claims (i.e., a description of
what data the holder wants to release). For test cases, an additional third
property is contained, which is the expected output of the verifier.

Implementers of SD-JWT libraries are advised to run at least the following tests:

  - End-to-end: The issuer creates an SD-JWT according to the input data, the
    holder discloses the claims according to the holder disclosed claims, and
    the verifier verifies the SD-JWT and outputs the expected verified contents.
    The test passes if the output of the verifier matches the expected verified
    contents.
  - Issuer-direct-to-holder: The issuer creates an SD-JWT according to the input
    data and the whole SD-JWT is put directly into the Verifier for consumption.
    (Note that this is possible because an SD-JWT presentation differs only by
    one '~' character from the SD-JWT issued by the issuer if key binding is
    not enforced. This character can easily be added in the test execution.)
    This test simulates that a holder releases all data contained in the SD-JWT
    and is useful to verify that the Issuer put all data into the SD-JWT in a
    correct way. The test passes if the output of the verifier matches the input
    user claims (including all claims marked for selective disclosure).

In this library, the two tests are implemented in
[tests/test_e2e_testcases.py](tests/test_e2e_testcases.py) and
[tests/test_disclose_all_shortcut.py](tests/test_disclose_all_shortcut.py),
respectively.

The `specification.yml` file has the following format for test cases (find more examples in [tests/testcases](tests/testcases)):

### Input data: `user_claims`

`user_claims` is a YAML dictionary with the user claims, i.e., the payload that
is to be turned into an SD-JWT. **Object keys** and **array elements** (and only
those!) can be marked for selective disclosure at any level in the data by
applying the YAML tag "!sd" to them.

This is an example of an object where two out of three keys are marked for selective disclosure:

```yaml
user_claims:
  is_over:
    "13": True          # not selectively disclosable - always visible to the verifier
    !sd "18": False     # selectively disclosable
    !sd "21": False     # selectively disclosable
```

The following shows an array with two elements, where both are marked for selective disclosure:

```yaml
user_claims:
  nationalities:
    - !sd "DE"
    - !sd "US"
```

The following shows an array with two elements that are both objects, one of which is marked for selective disclosure:

```yaml
user_claims:
  addresses:
    - street: "123 Main St"
      city: "Anytown"
      state: "NY"
      zip: "12345"
      type: "main_address"

    - !sd
      street: "456 Main St"
      city: "Anytown"
      state: "NY"
      zip: "12345"
      type: "secondary_address"
```

The following shows an object that has only one claim (`sd_array`) which is marked for selective disclosure. Note that within the array, there is no selective disclosure.

```yaml
user_claims:
  !sd sd_array:
    - 32
    - 23
```

### Holder Behavior: `holder_disclosed_claims`

`holder_disclosed_claims` is a YAML dictionary with the claims that the holder
discloses to the verifier. The structure must follow the structure of
`user_claims`, but elements can be omitted. The following rules apply:

 - For scalar values (strings, numbers, booleans, null), the value must be
   `True` or `yes` if the claim is disclosed and `False` or `no` if the claim
   should not be disclosed.
 - Arrays mirror the elements of the same array in `user_claims`. For each
   value, if it is not `False` or `no`, the value is disclosed. If an array
   element in `user_claims` is an object or array, an object or array can be
   provided here as well to describe which elements of that object/array should
   be disclosed or not, if applicable.
 - For objects, list all keys that are to be disclosed, using a value that is
   not `False` or `no`. As above, if the value is an object or array, it is used
   to describe which elements of that object/array should be disclosed or not,
   if applicable.

### Verifier Output: `expect_verified_user_claims`

Finally, `expect_verified_user_claims` describes what the verifier is expected
to output after successfully consuming the presentation from the holder. In
other words, after applying `holder_disclosed_claims` to `user_claims`, the
result is `expect_verified_user_claims`.

### Other Properties


When `key_binding` is set to `true`, a Key Binding JWT will be generated.

Using `serialization_format`, the serialization format of the SD-JWT can be
specified. The default is `compact`, but `json` is also supported.