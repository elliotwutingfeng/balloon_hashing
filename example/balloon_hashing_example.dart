import 'package:balloon_hashing/balloon_hashing.dart';
import 'package:convert/convert.dart';

void main() {
  const String password = 'buildmeupbuttercup';
  const String salt = 'JqMcHqUcjinFhQKJ';
  print(balloonHash(password, salt));
  // OUTPUT: 2ec8d833db5f88e584ab793950ecfb21657a3816edea8d9e73ea23c13ba2b740

  const int delta = 5;
  const int timeCost = 18;
  const int spaceCost = 24;
  final String bs =
      hex.encode(balloon(password, salt, spaceCost, timeCost, delta: delta));
  print(bs);
  // OUTPUT: 69f86890cef40a7ec5f70daff1ce8e2cde233a15bffa785e7efdb5143af51bfb
}
