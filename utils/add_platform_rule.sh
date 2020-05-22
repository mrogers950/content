#!/bin/bash

set -e

ACTION=$1
RULE_NAME=$2
OBJECT=$3
TITLE=$4
DESC=$5
YAMLPATH=$6
MATCH=$7
RULE_DIR="$(pwd)/applications/openshift"

ROOT_DIR=$(git rev-parse --show-toplevel)

OC=`which oc`
if [ -z "$KUBECONFIG" ]; then
  echo "need to set KUBECONFIG"
  exit 1
fi

if [ "$ACTION" == "create" ]; then
  if [ -z "$RULE_NAME" ]; then
    echo "use $0 $ACTION <rule_name> <type,name,namespace> <title> <description> <yamlpath> <match>"
    exit 1
  fi

  echo "creating rule $RULE_NAME"
  if [ -z "$OBJECT" ]; then
    echo "use $0 $ACTION $RULE_NAME <type,name,namespace> <title> <description> <yamlpath> <match>"
    exit 1
  fi

  if [ -z "$TITLE" ]; then
    TITLE="FILL THIS OUT"
  fi

  if [ -z "$DESC" ]; then
    DESC="FILL THIS OUT"
  fi

  if [ - "$YAMLPATH" ]; then
    YAMLPATH="FILL THIS OUT"
  fi
  
  if [ - "$MATCH" ]; then
    MATCH="FILL THIS OUT"
  fi

  RULE_PATH="$ROOT_DIR/$RULE_DIR/$RULE_NAME"

  IFS=','
  read -ra OBJARR <<< "$OBJECT"
  TYPE="${OBJARR[0]}"
  NAME="${OBJARR[1]}"
  NS="${OBJARR[2]}"
  CMDLINE="$OC get $TYPE/$NAME --loglevel=6"
  if [ ! -z "$NS" ]; then
    CMDLINE+=" -n $NS"
  fi

  # Try to pull out the resource URL from the debug output.
  URL=`eval "$CMDLINE" 2>&1 | grep -m1 GET | awk '{ print $6 }' | sed 's/^https\:\/\/.*443//'`
  if [ "$URL" == *"timeout"* ]; then
      echo "received a timeout response from the server. Make sure it is responding and try again."
      exit 1
  fi
  echo "Using URL path $URL, creating $RULE_PATH"

  mkdir -p "$RULE_PATH/oval"
  cat > "$RULE_PATH/rule.yaml" <<EOF
prodtype: ocp4

title: ${TITLE}

description: TBD

rationale: TBD

identifiers:
    cce@ocp4: 84209-6

severity: medium

warnings:
    - general: |-
        {{{ openshift_cluster_settings("${URL}") | indent(8) }}}
EOF
  
  cat > "$RULE_PATH/oval/shared.xml" <<EOF
{{% set YAML_TEST_OVAL_VERSION = [5, 11] %}}

{{% if target_oval_version >= YAML_TEST_OVAL_VERSION %}}
<def-group>
        <definition class="compliance" version="1" id="{{{ rule_id }}}">
      <metadata>
        <title>${TITLE}</title>
        {{{- oval_affected(products) }}}
        <description>${DESC}</description>
      </metadata>
      <criteria operator="AND">
        <criterion comment="${DESC}" negate="false" test_ref="test_{{{ rule_id }}}"/>
        <criterion comment="Make sure that there is the actual file to scan" test_ref="test_file_for_{{{ rule_id }}}"/>
      </criteria>
    </definition>

    <ind:yamlfilecontent_test id="test_{{{ rule_id }}}" check="at least one" comment="Find one match" version="1">
            <ind:object object_ref="object_{{{ rule_id }}}"/>
            <ind:state state_ref="state_{{{ rule_id }}}"/>
    </ind:yamlfilecontent_test>

    <local_variable id="{{{ rule_id }}}_dump_location" datatype="string" comment="The actual filepath of the file to scan." version="1">
       <concat>
               <variable_component var_ref="ocp_data_root"/>
               <literal_component>${URL}</literal_component>
       </concat>
    </local_variable>

    <unix:file_test id="test_file_for_{{{ rule_id }}}" check="only one" comment="Find the actual file to be scanned." version="1">
            <unix:object object_ref="object_file_for_{{{ rule_id }}}"/>
    </unix:file_test>

    <unix:file_object id="object_file_for_{{{ rule_id }}}" version="1">
      <unix:filepath var_ref="{{{ rule_id }}}_dump_location"/>
    </unix:file_object>

    <ind:yamlfilecontent_object id="object_{{{ rule_id }}}" version="1">
      <ind:filepath var_ref="{{{ rule_id }}}_dump_location"/>
      <ind:yamlpath>${YAMLPATH}</ind:yamlpath>
    </ind:yamlfilecontent_object>

    <ind:yamlfilecontent_state id="state_{{{ rule_id }}}" version="1">
            <ind:value_of datatype="string" operation="pattern match">${MATCH}</ind:value_of>
    </ind:yamlfilecontent_state>

   <external_variable comment="Root of downloaded stuff" datatype="string" id="ocp_data_root" version="1" />
</def-group>
{{% endif  %}}
EOF

  exit 0
elif [ "$ACTION" == "clustertest" ]; then
  if [ -z "$RULE_NAME" ]; then
    echo "use $0 $ACTION <rule_name>"
    exit 1
  fi

  NS=$2
  if [ -z "$NS" ]; then
    NS="openshift-compliance"
  fi

  cat > "$ROOT_DIR"/ocp4/profiles/"$RULE_NAME".profile <<EOF
documentation_complete: true

title: 'Test Profile for ${RULE_NAME}'

description: |-
    Test Profile
selections:

    - ${RULE_NAME}
EOF

  echo "cluster-testing rule $RULE_NAME. Make sure compliance-operator is deployed."
  sh "$ROOT_DIR"/utils/build_ds_container.sh ocp4
  $OC apply -n "$NS" -f - <<EOF
apiVersion: compliance.openshift.io/v1alpha1
kind: ComplianceScan
metadata:
  name: ${RULE_NAME}-test
spec:
  # Add fields here
  scanType: Platform
  profile: xccdf_org.ssgproject.content_profile_${RULE_NAME}
  content: ssg-ocp4-ds.xml
  contentImage: image-registry.openshift-image-registry.svc:5000/openshift-compliance/openscap-ocp4-ds:latest
EOF

  exit 0
elif [ "$ACTION" == "test" ]; then
  if [ -z "$RULE_NAME" ]; then
    echo "use $0 $ACTION <rule_name> <operator-namespace>"
    exit 1
  fi
  echo "testing rule $RULE_NAME"
else
  echo "use $0 {test,create}"
  exit 1
fi

