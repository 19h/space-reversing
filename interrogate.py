import os
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError, EncodeError
import logging

# Load the compiled descriptor set from file.
with open("merged_descriptor_set.pb", "rb") as f:
    fds = descriptor_pb2.FileDescriptorSet()
    fds.ParseFromString(f.read())

# Build a DescriptorPool and register all FileDescriptorProtos.
pool = descriptor_pool.DescriptorPool()
for fd_proto in fds.file:
    pool.Add(fd_proto)

# Instantiate a dynamic MessageFactory based on the pool.
factory = message_factory.MessageFactory(pool)

# Recursively extract fully qualified message type names from a FileDescriptorProto.
def get_message_types(fd_proto):
    package = fd_proto.package
    for msg in fd_proto.message_type:
        yield from _get_nested_types(package, msg)

def _get_nested_types(prefix, msg_proto):
    fullname = f"{prefix}.{msg_proto.name}" if prefix else msg_proto.name
    yield fullname
    for nested in msg_proto.nested_type:
        yield from _get_nested_types(fullname, nested)

# Gather all candidate message type names from the descriptor set.
candidate_types = []
for fd_proto in fds.file:
    candidate_types.extend(list(get_message_types(fd_proto)))

# Directory containing raw protobuf binary dumps.
dump_dir = "/home/null/Games/star-citizen/drive_c/users/null/sc_dumps"

# Process each binary file.
for fname in os.listdir(dump_dir):
    fpath = os.path.join(dump_dir, fname)
    if not os.path.isfile(fpath):
        continue
    with open(fpath, "rb") as f:
        raw_data = f.read()

    best_candidate = None
    best_score = None
    candidate_scores = []  # Debug: store (type, score) pairs.

    # Iterate over candidate schemas.
    for msg_type in candidate_types:
        try:
            # Retrieve the Descriptor for the candidate.
            descriptor = pool.FindMessageTypeByName(msg_type)
            # Create a dynamic message class and instance.
            MsgClass = factory.GetPrototype(descriptor)
            message_instance = MsgClass()
            # Attempt dynamic parsing.
            message_instance.MergeFromString(raw_data)
            try:
                # Serialize to verify message integrity.
                parsed_data = message_instance.SerializeToString()
            except EncodeError as e:
                logging.debug("EncodeError for %s using %s: %s", fname, MsgClass.__name__, e)
                continue
            except Exception as e:
                logging.debug("Unexpected error in SerializeToString for %s using %s: %s", fname, MsgClass.__name__, e)
                continue
            # Heuristic: difference between raw binary length and parsed message length.
            score = abs(len(raw_data) - len(parsed_data))
            candidate_scores.append((msg_type, score))
            if best_score is None or score < best_score:
                best_score = score
                best_candidate = msg_type
        except (KeyError, DecodeError):
            # Candidate rejected: type not found or parsing failed.
            continue

    # Report the best-matching schema candidate for the file.
    print(f"File: {fname}")
    if best_candidate:
        print(f"  Best candidate: {best_candidate} (score: {best_score})")
    #else:
    #    print("  No matching schema candidate found.")
    # Uncomment below for detailed candidate scoring:
    # for cand, score in sorted(candidate_scores, key=lambda x: x[1]):
    #     print(f"    Candidate: {cand}, score: {score}")
