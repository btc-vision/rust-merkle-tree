import { Address, EcKeyPair } from '@btc-vision/transaction';
import { networks } from '@btc-vision/bitcoin';

export const NETWORK = networks.regtest;

export function randomAddress(): Address {
    const rndKeyPair = EcKeyPair.generateRandomKeyPair(NETWORK);
    const rndBytes = crypto.getRandomValues(new Uint8Array(32));

    return new Address(rndBytes, rndKeyPair.publicKey);
}
