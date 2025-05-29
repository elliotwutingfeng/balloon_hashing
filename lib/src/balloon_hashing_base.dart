import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

Map<String, Hash> hashFunctions = {
  'md5': md5,
  'sha1': sha1,
  'sha224': sha224,
  'sha256': sha256,
  'sha384': sha384,
  'sha512': sha512,
};

const String hashType = 'sha256';

Uint8List _int32ToBytes(int value) =>
    Uint8List(8)..buffer.asByteData().setInt32(0, value, Endian.little);

BigInt _bytesToInteger(List<int> bytes) {
  BigInt value = BigInt.from(0);

  for (int i = 0; i < bytes.length; i++) {
    value += BigInt.from(bytes[i]) * BigInt.from(256).pow(i);
  }

  return value;
}

/// Concatenate all the arguments [args] and hash the result.
/// Note that the hash function used can be modified
/// in the global parameter `hashType`.
List<int> _hashFunc(List<Object> args) {
  List<int> t = [];

  for (final arg in args) {
    if (arg is int) {
      t += _int32ToBytes(arg);
    } else if (arg is String) {
      t += utf8.encode(arg);
    } else if (arg is List<int>) {
      t += arg;
    }
  }

  return hashFunctions[hashType]!.convert(t).bytes;
}

/// First step of the algorithm. Fill up a buffer [buf] with
/// pseudorandom bytes derived from the password and salt
/// by computing repeatedly the hash function on a combination
/// of the password and the previous hash.
/// [cnt] is used in a security proof (read the paper).
int _expand(List<List<int>> buf, int cnt, int spaceCost) {
  for (int s = 1; s < spaceCost; s++) {
    buf.add(_hashFunc([cnt, buf[s - 1]]));
    cnt++;
  }
  return cnt;
}

/// Second step of the algorithm. Mix [timeCost] number
/// of times the pseudorandom bytes in the buffer. At each
/// step in the for loop, update the nth block to be
/// the hash of the n-1th block, the nth block, and [delta]
/// other blocks chosen at random from the buffer [buf].
void _mix(
  List<List<int>> buf,
  int cnt,
  int delta,
  List<int> salt,
  int spaceCost,
  int timeCost,
) {
  for (int t = 0; t < timeCost; t++) {
    for (int s = 0; s < spaceCost; s++) {
      buf[s] = _hashFunc([cnt, buf[s == 0 ? buf.length - 1 : s - 1], buf[s]]);
      cnt++;
      for (int i = 0; i < delta; i++) {
        final List<int> idxBlock = _hashFunc([t, s, i]);
        final int other =
            (_bytesToInteger(_hashFunc([cnt, salt, idxBlock])) %
                    (BigInt.from(spaceCost)))
                .toInt();
        cnt++;
        buf[s] = _hashFunc([cnt, buf[s], buf[other]]);
        cnt++;
      }
    }
  }
}

/// Final step. Return the last value in the buffer [buf].
List<int> _extract(List<List<int>> buf) => buf[buf.length - 1];

/// Main function that collects all the substeps. As
/// previously mentioned, first `expand`, then `mix`, and
/// finally `extract`. Note the result is returned as List&lt;int&gt;,
/// for a more friendly function with default values
/// that returns a hex String, see the function `balloonHash`.
List<int> balloon(
  String password,
  String salt,
  int spaceCost,
  int timeCost, {
  int delta = 3,
}) => _balloon(password, utf8.encode(salt), spaceCost, timeCost, delta: delta);

/// Implements steps outlined in `balloon`.
List<int> _balloon(
  String password,
  List<int> salt,
  int spaceCost,
  int timeCost, {
  int delta = 3,
}) {
  final List<List<int>> buf = [
    _hashFunc([0, password, salt]),
  ];
  int cnt = 1;

  cnt = _expand(buf, cnt, spaceCost);
  _mix(buf, cnt, delta, salt, spaceCost, timeCost);

  return _extract(buf);
}

/// A more friendly client function that just takes
/// a [password] and a [salt] and outputs the hash as a hex String.
String balloonHash(String password, String salt) {
  const int delta = 4;
  const int timeCost = 20;
  const int spaceCost = 16;

  return hex.encode(balloon(password, salt, spaceCost, timeCost, delta: delta));
}

/// M-core variant of the Balloon hashing algorithm. Note the result
/// is returned as List&lt;int&gt;, for a more friendly function with default
/// values that returns a hex String, see the function `balloonMHash`.
Future<List<int>> balloonM(
  String password,
  String salt,
  int spaceCost,
  int timeCost,
  int parallelCost, {
  int delta = 3,
}) async {
  final List<List<int>> results = await Future.wait<List<int>>([
    for (int p = 0; p < parallelCost; p++)
      Future(
        () async => _balloon(
          password,
          utf8.encode(salt) + _int32ToBytes(p + 1),
          spaceCost,
          timeCost,
          delta: delta,
        ),
      ),
  ]);

  final List<int> output = results.reduce((current, next) {
    final int shorterLength = current.length < next.length
        ? current.length
        : next.length;
    return [for (int i = 0; i < shorterLength; i++) current[i] ^ next[i]];
  });

  return _hashFunc([password, salt, output]);
}

/// A more friendly client function that just takes
/// a [password] and a [salt] and outputs the hash as a hex string.
/// This uses the M-core variant of the Balloon hashing algorithm.
Future<String> balloonMHash(String password, String salt) async {
  const int delta = 4;
  const int timeCost = 20;
  const int spaceCost = 16;
  const int parallelCost = 4;

  return hex.encode(
    await balloonM(
      password,
      salt,
      spaceCost,
      timeCost,
      parallelCost,
      delta: delta,
    ),
  );
}

/// Return true if the [hash] to check against matches [password]
/// when hashed with [salt] (user defined random value for security),
/// [spaceCost] (size of the buffer), [timeCost] (number of rounds to mix),
/// and [delta] (number of random blocks to mix with).
bool verify(
  String hash,
  String password,
  String salt,
  int spaceCost,
  int timeCost, {
  int delta = 3,
}) {
  final String computedHash = hex.encode(
    balloon(password, salt, spaceCost, timeCost, delta: delta),
  );
  if (computedHash.length != hash.length) {
    return false;
  }
  int mismatch = 0; // String comparison in constant time
  for (int i = 0; i < computedHash.length; i++) {
    mismatch |= computedHash.codeUnitAt(i) ^ hash.codeUnitAt(i);
  }
  return mismatch == 0;
}

/// Return true if the [hash] to check against matches [password]
/// when hashed with [salt] (user defined random value for security),
/// [spaceCost] (size of the buffer), [timeCost] (number of rounds to mix),
/// [parallelCost] (number of concurrent instances),
/// and [delta] (number of random blocks to mix with).
/// This uses the M-core variant of the Balloon hashing algorithm.
Future<bool> verifyM(
  String hash,
  String password,
  String salt,
  int spaceCost,
  int timeCost,
  int parallelCost, {
  int delta = 3,
}) async {
  final String computedHash = hex.encode(
    await balloonM(
      password,
      salt,
      spaceCost,
      timeCost,
      parallelCost,
      delta: delta,
    ),
  );
  if (computedHash.length != hash.length) {
    return false;
  }
  int mismatch = 0; // String comparison in constant time
  for (int i = 0; i < computedHash.length; i++) {
    mismatch |= computedHash.codeUnitAt(i) ^ hash.codeUnitAt(i);
  }
  return mismatch == 0;
}
