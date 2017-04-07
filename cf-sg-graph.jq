# Generic map for JSON
def fmap(f):
  if type == "object" then map_values(f) else if type == "array" then map(f) else . end end;

# Catamorphism, same as https://stedolan.github.io/jq/manual/#walk(f) in newer versions
def cata(f):
  fmap(cata(f)) | f;

# Ignore Fn::Sub intrinsic functions and replace them with their arguments
def eliminate_subs: cata(
  if type == "object" and has("Fn::Sub") then
    if (.["Fn::Sub"] | type) == "array" then .["Fn::Sub"][0] else .["Fn::Sub"] end
  else
    .
  end
);

# Ignore Fn::ImportValue intrinsic functions and replace them with their arguments
def eliminate_imports: cata(
  if type == "object" and has("Fn::ImportValue") then
    { Ref: .["Fn::ImportValue"] }
  else
    .
  end
);

# Reference to the subject security group from a security rule
def node_ref:
  .GroupId.Ref // .GroupName.Ref;

# Reference to the source security group from a security rule
def source_node_ref:
  .SourceSecurityGroupId.Ref // .SourceSecurityGroupName.Ref // .CidrIp;

# Reference to the destination security group from a security rule
def target_node_ref:
  .DestinationSecurityGroupId.Ref // .DestinationSecurityGroupName.Ref // .CidrIp;

# Pretty-print -1 as * for IP protocols and port numbers
def wildcard(value):
  if value == "-1" then "*" else value end;

# Label an edge in the graph with the details about the allowed connections
def edge_label(proto; from; to):
  wildcard(proto) + " " +
  (if proto == "icmp" then
    wildcard(from) + " " + wildcard(to)
  else
    if from == to then from else from + "-" + to end
  end);

# Gather all security rules of a given type (inbound or outbound) to form an array of edges in the graph
def edges(type; source; target):
  .Resources | map(
    select(.Type == type) | .Properties |
    {
      source: source,
      target: target,
      label: edge_label(.IpProtocol; .FromPort; .ToPort),
      directed: true,
      metadata: { type: type }
    }
  );

# Combine the edges for each pair of nodes, aggregating their labels
def combine_edges:
  group_by(.source, .target, .metadata.type) | map(
    . as $all | .[0] |
    .label = "   " + ([$all[].label] | join(", "))
  );

# Gather all edges for the graph
def edges:
  edges("AWS::EC2::SecurityGroupEgress"; node_ref; target_node_ref) +
  edges("AWS::EC2::SecurityGroupIngress"; source_node_ref; node_ref) |
  combine_edges;

# Gather all nodes referenced by the edges, fetching pretty descriptions where possible
def nodes:
  . as $input |
  edges | map(.source, .target) | unique | map(
    . as $id |
    {
      id: $id,
      label: ($input.Resources[$id].Properties.GroupDescription // $id)
    }
  );

# Build the graph
def graph:
  eliminate_subs | eliminate_imports |
  {
    graph: {
      directed: true,
      nodes: nodes,
      edges: edges
    }
  };
