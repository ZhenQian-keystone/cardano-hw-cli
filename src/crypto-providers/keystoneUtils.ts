import {
    QRHardwareCall, CryptoKeypath, PathComponent, KeyDerivation, KeyDerivationSchema, Curve,
    DerivationAlgorithm, QRHardwareCallType, CryptoMultiAccounts, QRHardwareCallVersion,
} from '@keystonehq/bc-ur-registry';
import { UR, UREncoder, URDecoder } from '@ngraveio/bc-ur';
import { Actions, TransportHID } from '@keystonehq/hw-transport-usb';
import { throwTransportError, Status } from '@keystonehq/hw-transport-error';
import KeystoneSDK, { CardanoCatalystRequestProps, CardanoSignCip8MessageData, CardanoSignDataRequestProps } from "@keystonehq/keystone-sdk"
const pathToKeypath = (path: string): CryptoKeypath => {
    const paths = path.replace(/[m|M]\//, '').split('/');
    const pathComponents = paths.map(path => {
        const index = parseInt(path.replace('\'', ''), 10);
        const isHardened = path.endsWith('\'');
        return new PathComponent({ index, hardened: isHardened });
    });
    return new CryptoKeypath(pathComponents);
};
const parseResponoseUR = (urPlayload: string): UR => {
    const decoder = new URDecoder();
    decoder.receivePart(urPlayload);
    if (!decoder.isComplete()) {
        throwTransportError(Status.ERR_UR_INCOMPLETE);
    }
    const resultUR = decoder.resultUR();
    return resultUR;
};

export default class Cardano {
    private transport: TransportHID;
    private mfp: string | undefined;

    /**
     * Constructs a new instance of the class.
     *
     * @param transport - An object of type TransportWebUSB
     * @param mfp - Optional parameter of type string, default is undefined, but the mfp should exist in the signing process.
     */
    constructor(transport: TransportHID, mfp?: string) {
        this.transport = transport;
        if (mfp) {
            this.mfp = mfp;
        }
    }

    private precheck() {
        if (!this.transport) {
            throwTransportError(Status.ERR_TRANSPORT_HAS_NOT_BEEN_SET);
        }
        if (!this.mfp) {
            throw new Error('missing mfp for this wallet');
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private async sendToDevice(actions: Actions, data: any): Promise<any> {
        return this.transport.send(actions, data);
    }

    private async checkDeviceLockStatus(): Promise<boolean> {
        const result = await this.sendToDevice(Actions.CMD_CHECK_LOCK_STATUS, '');
        return result.payload;
    }
    async getDeviceInfo(): Promise<{ firmwareVersion: string, walletMFP: string }> {
        const result = await this.sendToDevice(Actions.CMD_GET_DEVICE_VERSION, '');
        return Promise.resolve(result)
    }

    async getExtendedPublicKeys(paths: string[]): Promise<{ publicKey: string, mfp: string, chainCode: string }[]> {
        // Send a request to the device to get the address at the specified path
        const curve = Curve.ed25519;
        const algo = DerivationAlgorithm.bip32ed25519;
        const schemas = [];
        for (const path of paths) {
            const kds = new KeyDerivationSchema(pathToKeypath(path), curve, algo, 'ADA');
            schemas.push(kds);
        }
        const keyDerivation = new KeyDerivation(schemas);
        const hardwareCall = new QRHardwareCall(QRHardwareCallType.KeyDerivation, keyDerivation, 'Keystone USB SDK', QRHardwareCallVersion.V1);
        const ur = hardwareCall.toUR();
        const encodedUR = new UREncoder(ur, Infinity).nextPart().toUpperCase();

        const response = await this.sendToDevice(Actions.CMD_RESOLVE_UR, encodedUR);
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        const resultUR = parseResponoseUR(response.payload);

        const account = CryptoMultiAccounts.fromCBOR(resultUR.cbor);

        const keys = account.getKeys();
        const result = []
        for (const key of keys) {
            result.push({
                publicKey: key.getKey().toString('hex'),
                mfp: account.getMasterFingerprint().toString('hex'),
                chainCode: key.getChainCode().toString('hex')
            })
        }
        return result
    }

    async signCardanoDataTransaction(
        props: CardanoSignDataRequestProps
    ): Promise<{ signature: Buffer }> {
        this.precheck();
        const keystoneSDK = new KeystoneSDK();
        const ur = keystoneSDK.cardano.generateSignDataRequest(props);
        const encodedUR = new UREncoder(ur, Infinity).nextPart().toUpperCase();
        const response = await this.sendToDevice(Actions.CMD_RESOLVE_UR, encodedUR);
        const resultUR = parseResponoseUR(response.payload);
        // parse signature
        const signature = keystoneSDK.cardano.parseSignDataSignature(resultUR);
        return {
            signature: Buffer.from(signature.signature, 'hex'),
        };
    }

    async signCardanoTransaction({
        signData,
        utxos,
        extraSigners,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }: { signData: Buffer, utxos: any, extraSigners: any }): Promise<{ signature: Buffer }> {
        const requestId = '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d';
        const origin = 'cardano-cli-wallet';
        this.precheck();
        const keystoneSDK = new KeystoneSDK();
        const ur = keystoneSDK.cardano.generateSignRequest({
            signData,
            utxos,
            extraSigners,
            requestId,
            origin,
        });
        const encodedUR = new UREncoder(ur, Infinity).nextPart().toUpperCase();
        const response = await this.sendToDevice(Actions.CMD_RESOLVE_UR, encodedUR);
        const resultUR = parseResponoseUR(response.payload);
        // parse signature
        const cardanoSignResult = keystoneSDK.cardano.parseSignature(resultUR);
        const witnessSet = cardanoSignResult.witnessSet
        // split 32 bytes
        const signature = witnessSet.slice(-128)
        return {
            signature: Buffer.from(signature, 'hex'),
        };
    }


    async signCardanoCatalystRequest(props: CardanoCatalystRequestProps): Promise<{ signature: Buffer }> {
        const keystoneSDK = new KeystoneSDK();
        const ur = keystoneSDK.cardano.generateCatalystRequest(props);
        const encodedUR = new UREncoder(ur, Infinity).nextPart().toUpperCase();
        const response = await this.sendToDevice(Actions.CMD_RESOLVE_UR, encodedUR);
        const resultUR = parseResponoseUR(response.payload);
        // parse signature
        const signature = keystoneSDK.cardano.parseCatalystSignature(resultUR);
        return {
            signature: Buffer.from(signature.signature, 'hex'),
        };
    }



    async signCardanoCip8DataTransaction(
        props: CardanoSignCip8MessageData
    ): Promise<{ signature: string, publicKey: string, addressFieldHex: string }> {
        this.precheck();
        const keystoneSDK = new KeystoneSDK();
        const ur = keystoneSDK.cardano.generateSignCip8DataRequest(props);
        const encodedUR = new UREncoder(ur, Infinity).nextPart().toUpperCase();
        const response = await this.sendToDevice(Actions.CMD_RESOLVE_UR, encodedUR);
        const resultUR = parseResponoseUR(response.payload);
        const result = keystoneSDK.cardano.parseSignCip8DataSignature(resultUR);
        return {
            signature: result.signature,
            publicKey: result.publicKey,
            addressFieldHex: result.addressField
        };
    }
}
