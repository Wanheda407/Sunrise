# Catalyst completion fixture

`catalyst_completion_86657.txt` contains the numeric unlock requirements for the 45
released catalysts in client build `86657.20.08.23`, in item-definition order.
Each line is:

```text
acquisition_slot flag_count [completion_slot account_row]... value_count [value_slot minimum]...
```

`65535` means a completion flag has no account mapping and needs a Family-5
override. The acquisition slots have no account mapping. Fifteen completion flags
map to the account acquired-flag bank.

Provenance: catalyst relations extracted by Sunrise master `a57dc9a`, joined to
the installed investment root's slot 111, flag-map tag `0x81319322`, descriptor
`+8`. Its 11,923 rows have stride 8 and destination slot at `+4`; the row number
is the account bank index. This fixture contains numeric requirements only, not
package payloads or account data. Tests use synthetic item identities.

The test's 43 authored flags match `Sunrise/resources/default_settings.json` at
that revision. With the old projection: 43 authored + 25 artifact + 62 catalyst
flags = 130. The corrected projection retains 43 authored + 47 catalyst flags =
90. Artifact ownership travels through the existing character bank, and 15
catalyst completion flags through the account bank. Both carriers retain the
native 100-row Family-5 bound.

Run on Windows:

```powershell
cmake -S tests -B build/tests -G "Visual Studio 17 2022" -A x64
cmake --build build/tests --config Release
ctest --test-dir build/tests -C Release --output-on-failure
```
