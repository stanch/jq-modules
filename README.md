# Various jq modules

## `cf-sg-graph.jq`

This script produces a [JSON Graph](http://jsongraphformat.info/) representation of the security rules
found in a given [CloudFormation](https://aws.amazon.com/cloudformation/) template.

Note that currently only rules specified as resources are supported.

Prerequisites:

    sudo apt-get install jq graphviz
    sudo npm install -g jgf-dot
    mkdir ~/.jq
    curl https://raw.githubusercontent.com/stanch/jq-modules/master/cf-sg-graph.jq > ~/.jq/cf-sg-graph.jq

Usage:

    jq 'include "cf-sg-graph"; graph' template.json | jgfdot | dot -Tsvg -otest.svg -Granksep=1.5
