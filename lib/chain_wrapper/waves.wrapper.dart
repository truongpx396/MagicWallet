import 'dart:convert';

import 'package:bs58/bs58.dart';
import 'package:hex/hex.dart';
import 'package:http/http.dart' as http;
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/src/digests/digests.dart' as pn;
import 'package:cryptography/cryptography.dart';
import 'package:web3dart/crypto.dart';

import '../data_structure/ui_transaction.dart';
import '../utils/secure_storage.dart';
// import 'package:curve25519_vrf/curve25519_vrf.dart' as curve25519_vrf;

class WavesWrapper {
  static Future<BigInt> getTokenBalance(String wavesAddress) {
    final response = http.get(Uri.parse(
        'https://nodes.wavesnodes.com/addresses/balance/' + wavesAddress));
    return response.then((value) {
      return BigInt.from(jsonDecode(value.body)['balance']);
    });
  }

  static Future<BigInt> getTokenPrice(
      String routerAddress, List<String> pathString, int decimals) {
    return Future.value(BigInt.zero);
  }

  static Future<dynamic> getTokenBalanceByStorageWalletAddress(
      String tokenAddress) async {
    final wavesAddress = await SecureStorage.getWavesAddress();
    return getTokenBalance(wavesAddress!);
  }

  static Future<String> getAddressFromSeed(String seed) async {
    var encodedSeed =
        "1111" + base58.encode(Uint8List.fromList(seed.codeUnits)).toString();
    var decodedSeed = base58.decode(encodedSeed);
    var accountSeedByte = pn.Hash.blake2b(decodedSeed, digestSize: 32);
    var accountSeed = keccak256(accountSeedByte);
    var accountSeedHash = pn.Hash.sha256(accountSeed);
    final algorithm = Cryptography.instance.x25519();
    final keyPair = await algorithm.newKeyPairFromSeed(accountSeedHash);
    final publicKey = await keyPair.extractPublicKey();
    var address = [1, 87] +
        keccak256(
                pn.Hash.blake2b(publicKey.bytes.toUint8List(), digestSize: 32))
            .sublist(0, 20);
    var checksum =
        keccak256(pn.Hash.blake2b(address.toUint8List(), digestSize: 32))
            .sublist(0, 4);
    address.addAll(checksum);

    return Future.value(base58.encode(address.toUint8List()));
  }

  static Future<int> estimateFee() async {
    String? publicKey = await SecureStorage.getWavesPublicKey();
    String? address = await SecureStorage.getWavesAddress();

    final response = await http.post(
      Uri.parse('https://nodes.wavesnodes.com/transactions/calculateFee'),
      headers: <String, String>{
        'Content-Type': 'application/json',
      },
      body: json.encode({
        "type": 4,
        "version": 2,
        "sender": address,
        "senderPublicKey": publicKey,
        "recipient": address,
        "amount": 1
      }),
    );
    return jsonDecode(response.body)['feeAmount'];
  }

  static Future<String> sendToken(String recipient, int amount) async {
    String? publicKey = await SecureStorage.getWavesPublicKey();
    String? privateKey = await SecureStorage.getWavesPrivateKey();

    int timestamp = DateTime.now().millisecondsSinceEpoch;
    int txFee = await estimateFee();
    List<int> dataList = [4, 2];
    dataList.addAll(base58.decode(publicKey!));
    dataList.addAll([0, 0]);
    dataList.addAll(HEX
        .decode((BigInt.from(timestamp).toRadixString(16).padLeft(16, "0"))));
    dataList.addAll(
        HEX.decode((BigInt.from(amount).toRadixString(16).padLeft(16, "0"))));
    dataList.addAll(
        HEX.decode((BigInt.from(txFee).toRadixString(16).padLeft(16, "0"))));
    dataList.addAll(base58.decode(recipient!));
    dataList.addAll([0, 0]);

    final signature;
    // final signature = curve25519_vrf.Curve25519().sign(
    //     curve25519_vrf.KeyPair(curve25519_vrf.PublicKey(base58.decode(publicKey)), curve25519_vrf.PrivateKey(base58.decode(privateKey!))),
    //     Uint8List.fromList(dataList),
    //     curve25519_vrf.SignatureType.STANDARD);
    List<int> signatureBytes = <int>[];
    // for (var element in signature.bytes) {
    //   signatureBytes.add(element!);
    // }

    final encodedSignature = base58.encode(Uint8List.fromList(signatureBytes));
    final response = await http.post(
      Uri.parse('https://nodes.wavesnodes.com/transactions/broadcast'),
      headers: <String, String>{
        'Content-Type': 'application/json',
      },
      body: json.encode({
        "type": 4,
        "version": 2,
        "senderPublicKey": publicKey,
        "recipient": recipient,
        "amount": amount,
        "fee": txFee,
        "timestamp": timestamp,
        "signature": encodedSignature,
        "proofs": [encodedSignature]
      }),
    );
    return jsonDecode(response.body)['id'];
  }

  static Future<UITransaction> getTransactionInfoByHash(
      String transactionHash, String tokenAddress) async {
    final response = await http.get(Uri.parse(
        'https://nodes.wavesnodes.com/transactions/info/' + transactionHash));
    final responseJson = jsonDecode(response.body);
    return UITransaction(
        responseJson['recipient'], BigInt.from(responseJson['amount']), true);
  }
}
