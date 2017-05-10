// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

namespace MyNamespace {
    #define WN 48
    #define WK 5
    #include "zen/src/pow/tromp/equi.h"
    #include "pow/tromp/equi_miner.h"
    #include "crypto/equihash.h"
    #include "metrics.h"
}

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ZEN";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * ZEN Network Magic Start Value
         */

        pchMessageStart[0] = 0x63;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x73;
        pchMessageStart[3] = 0x68;

        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 8033;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         * >>> from pyblake2 import blake2s
         * >>> 'Zclassic' + blake2s(b'No taxation without representation. BTC #437541 - 00000000000000000397f175a94dd3f530b957182eb2a9f7b79a44a94a5e0450').hexdigest()
         */
        const char* pszTimestamp = "Zclassic860413afe207aa173afee4fcfa9166dc745651c754a41ea8f155646f5aa828ac";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1478403829;
        genesis.nBits    = 0x1f07ffff;
        genesis.nNonce   = uint256S("0x000000000000000000000000000000000000000000000000000000000000021d");
        genesis.nSolution = ParseHex("009aaa951ca873376788d3002918d956e371bdf03c1afcfd8eea17867b5480d2e59a2a4dd52ed0d091af0c0909aa66ce2da97266926a9ea69b9ccca389bc120d9c4dbbae727ab9d6dfd1cd847df0ef0cc9bc989f11bdd6522429c15957daa3c5a2612522ded69857c148c0638611a19287599b47683c714b5774d0fcb1341cf4fc3a546a2441a19f02a55c6f9775749e57783b2abd5b25d41753d2f60892bbb4c3173d7787dbf5e50267324db218a14dd65f71bb02cf2566d3201800f866701db8c221424b75c639de58e7e40705157ae7d10da708ec2b9e71b9bc1ad34854a7bdf58d93766b6e291d3b545fa1f785a1a9829eccd525d16856f4317f0449d5c3516736f1e564f17690f13d3c939ad5516f1db70194902c20afd939168037fa404ec962dfbe752f79ac87a2cc3fd07bcd94d1975b1849cc739c0bc144ae4e75eda1bbed5b5ef8f65966257ec7b1fc6bb600e12e1c65c8c13a505f35dd363e07b6238211a0e502e36db5a620310b544360dd9b4a6cedabc34eeb530139daad50d4a5b6eaf4d50be4ba10e970ce984fb705376a3b0b4bf3f3778600f14e739e04406106f707085ab87ca70598c032b6717a54a9fd8ef72fdd78fb41fa9d45ad685caf77e0fc42e8e644634c24bc972f3ab0e3f0345854eda624045feb6bc9d20b5b1fc6903ebc64026e51da598c0d8711c452131a8fd2bbe01403af20e5db88afcd53b6107f001dae78b548d6a1581baca15359de83e54e75d8fc6374ca1edec17a9f4b06931162f9952575c5c3fb5dfc70a0f793049e781926daaafd4f4d330cf7d5635af1541f0d29e709a37c088d6d2e7aa09d15dfb9c2ae6c1ce661e85e9d89772eb47cfea00c621b66faf8a48cfa970b898dbd77b14e7bf44b742c00f76d2435f949f027132adb1e974551488f988e9fe379a0f86538ee59e26637a3d50bf400c7f52aa9457d77c3eb426628bb17909b26a6820d0772d4c6f74472f635e4c6e72272ce01fc475df69e10371457c55e0fbdf3a392850b9924da9c9a55792325c4318562593f0df8d39559065be03a22b1b6c21206aa1958a0d33257d89b74dea42a11aabf8eddbfe6136ab649744b704eb3e3d473654b588927dd9f486c1cd02639cf656ccbf2c4869c2ed1f2ba4ec55e69a42d5af6b3605a0cdf987734727c6fc1c1489870fb300139328c4d12eb6f5e8309cc09f5f3c29ab0957374113931ec9a56e7579446f12faacda9bd50899a17bd0f78e89ed70a723fdadfb1f4bc3317c8caa32757901604fb79ae48e22251c3b1691125ec5a99fabdf62b015bc817e1c30c06565a7071510b014058a77856a150bf86ab0c565b8bbbed159e2fb862c6215752bf3f0563e2bbbf23b0dbfb2de21b366b7e4cda212d69502643ca1f13ce362eef7435d60530b9999027dd39cd01fd8e064f1ccf6b748a2739707c9f76a041f82d3e046a9c184d83396f1f15b5a11eddb2baff40fc7b410f0c43e36ac7d8ff0204219abe4610825191fbb2be15a508c839259bfd6a4c5204c779fad6c23bbd37f90709654a5b93c6f93b4c844be12cd6cd2200afbf600b2ae9b6c133d8cdb3a85312a6d9948213c656db4d076d2bacd10577d7624be0c684bd1e5464bb39006a524d971cd2223ae9e23dea12366355b3cc4c9f6b8104df6abd23029ac4179f718e3a51eba69e4ebeec511312c423e0755b53f72ac18ef1fb445d7ab83b0894435a4b1a9cd1b473792e0628fd40bef624b4fb6ba457494cd1137a4da9e44956143068af9db98135e6890ef589726f4f5fbd45a713a24736acf150b5fb7a4c3448465322dccd7f3458c49cf2d0ef6dd7dd2ed1f1147f4a00af28ae39a73c827a38309f59faf8970448436fbb14766a3247aac4d5c610db9a662b8cb5b3e2");

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602"));
        assert(genesis.hashMerkleRoot == uint256S("0x19612bcf00ea7611d315d7f43554fa983c6e8c30cba17e52c679e0e80abf7d42"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("zencash.io", "mainnet-zen.zencash.io"));
        vSeeds.push_back(CDNSSeedData("zdeveloper.org", "mainnet-zen.zdeveloper.org"));
        vSeeds.push_back(CDNSSeedData("rotorproject.org", "mainnet-zen.rotorproject.org"));

        // guarantees the first 2 characters, when base58 encoded, are "t5"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xBF};
        // guarantees the first 2 characters, when base58 encoded, are "t7"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xC1};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zn"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xA5};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
            ( 30000, uint256S("0x000000005c2ad200c3c7c8e627f67b306659efca1268c9bb014335fdadc0c392"))
            ( 96577, uint256S("0x0000000177751545bd1af3ccf276ec2920d258453ab01f3d2f8f7fcc5f3a37b8")),
            1493090861,     // * UNIX timestamp of last checkpoint block
            241684,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1441            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Allocation script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 0*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 1*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 2*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 3*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 4*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 5*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 6*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 7*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 8*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 9*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 10*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 11*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 12*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 13*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 14*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 15*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 16*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 17*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 18*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 19*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 20*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 21*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 22*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 23*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 24*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 25*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 26*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 27*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 28*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 29*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 30*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 31*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 32*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 33*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 34*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 35*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 36*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 37*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 38*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 39*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 40*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 41*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 42*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 43*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 44*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 45*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 46*/
            "t5DiT2y2b5dBSzr51dQSVS2KgsGHYCRY5Js", /* main-index: 47*/
            //"t3PZ9PPcLzgL57XRSG5ND4WNBC9UTFb8DXv", /* main-index: 48*/
            //"t3L1WgcyQ95vtpSgjHfgANHyVYvffJZ9iGb", /* main-index: 49*/
            //"t3JtoXqsv3FuS7SznYCd5pZJGU9di15mdd7", /* main-index: 50*/
            //"t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
            //"t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN", /* main-index: 52*/
            //"t3T4WmAp6nrLkJ24iPpGeCe1fSWTPv47ASG", /* main-index: 53*/
            //"t3fP6GrDM4QVwdjFhmCxGNbe7jXXXSDQ5dv", /* main-index: 54*/
	};
        // Allocation script expects a vector of 2-of-3 multisig addresses
        vDAOAddress = {
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 0*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 1*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 2*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 3*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 4*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 5*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 6*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 7*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 8*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 9*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 10*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 11*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 12*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 13*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 14*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 15*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 16*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 17*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 18*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 19*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 20*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 21*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 22*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 23*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 24*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 25*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 26*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 27*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 28*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 29*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 30*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 31*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 32*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 33*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 34*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 35*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 36*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 37*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 38*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 39*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 40*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 41*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 42*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 43*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 44*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 45*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 46*/
            "t4yaWxgRwMSJyJM1mrwQmb5ftDuyGUCQsht", /* main-index: 47*/
            //"t3PZ9PPcLzgL57XRSG5ND4WNBC9UTFb8DXv", /* main-index: 48*/
            //"t3L1WgcyQ95vtpSgjHfgANHyVYvffJZ9iGb", /* main-index: 49*/
            //"t3JtoXqsv3FuS7SznYCd5pZJGU9di15mdd7", /* main-index: 50*/
            //"t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
            //"t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN", /* main-index: 52*/
            //"t3T4WmAp6nrLkJ24iPpGeCe1fSWTPv47ASG", /* main-index: 53*/
            //"t3fP6GrDM4QVwdjFhmCxGNbe7jXXXSDQ5dv", /* main-index: 54*/
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
        assert(vDAOAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "ZNT";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xcd;
        pchMessageStart[3] = 0xe6;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 18033;
        nMinerThreads = 0;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1479443947;
        genesis.nBits = 0x2007ffff;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000013");
        genesis.nSolution = ParseHex("002b24e10a5d2ab32b053a20ca6ebed779be1d935b1500eeea5c87aec684c6f934196fdfca6539de0cf1141544bffc5c0d1d4bab815fb5d8c2b195ccdf0755599ee492b9d98e3b79a178949f45485ad80dba38ec0461102adaa369b757ebb2bf8d75b5f67a341d666406d862a102c69800f20a7075be360a7eb2d315d78e4ce32c741f3baf7bf3e1e651976f734f367b1f126f62503b34d06d6e99b3659b2a47f5cfcf71c87e24e5023151d4af87454e7638a19b846350dd5fbc53e4ce1cce2597992b36cbcae0c24717e412c8df9ddca3e90c7629bd8c157c66d8906486943cf78e24d55dd4152f45eff49acf9fb9fddef81f2ee55892b38db940c404eaacf819588b83f0f761f1ba5b31a0ea1f8f4c5210638bbb59a2d8ddff9535f546b42a7eac5f3ee87616a075bddc3118b7f2c041f4b1e8dbcd11eea95835403066b5bb50cd23122dcb12166d75aafcfc1ca8f30580b4d48a5aa305657a06b4b650ed4633f2fa496235082feff65f70e19871f41b70632b53e57ddf38c207d631e5a56fa50bb71150f99427f73d82a439a5f70dfc7d8bbfc39d330ca7924527a5deb8950b9fa7020cfde5e07b84546e96764519ef6dd3fdc3a974abd342bdc7e4ee76bc11d5519541015afba1a0517fd347196aa326b0905a5916b83515c16f8f13105479c29f1eff3bc024ddbb07dcc672247cedc0d4ba32332ead0f13c58f50170642e16e076c34f5e75e3e8f5ac7f5238d67564fd385efecf972b0abf939a99bc7ef8f3a21cac21d2168706bbad3f4af66bb01cf61cfbc352a23797b62dcb5480bf2b7b277af233f5ce42a144d47119a89e1d114fa0bec2f13475b6b1df907bc3a429f1771afa3857bf16bfca3f76a5df14da62dc157fff4225bda73c3cfefa989edc24673bf932a024593da4c38b1a4628dd77ad919f4f7b7fb76976e696db69c89016ab30d9aa2d509f78d913d00ca9ac881aa759fc019b8c5e3eac6fddb4e0f044595e10d4997e29c79800f77cf1d97583d534db0f2726cba3739e7371eeffa2aca12b0d290ac45f44973f32f7675a5b49c94c4b608da2926555d16b7eb3670e12345a63f88797e5a5e21252c2c9463d7896001031a81bac0354336b35c5a10c93d9ae3054f6f6e4492f7c1f09a9d75034d5d0b220a9bb231e583659d5b6923a4e879326194de5c9805a02cb648508a8f9b6cd26dc17d322a478c1c599e1ec3adf2da6ce7a7e3a073b55cf30cf6b124f7700409abe14af8c60ab178579623916f165dbfd26f37056bf33c34f3af30939e1277376e4c5cba339f36381a05ef6481db033fb4c07a19e8655f8b12f9ab3c602e127b4ab1ee48e1c6a91382b54ed36ef9bb21b3bfa80a9107864dcb594dcad250e402b312607e648639631a3d1aeb17cfe3370202720ca8a46db15af92e8b46062b5bd035b24c35a592e5620d632faf1bf19a86df179fe52dd4cdbecd3cb7a336ca7489e4d1dc9433f1163c89d88c5eac36fc562496dc7583fe67c559c9a71cf89e9a0a59d5a14764926852d44a88d2ddb361d612ec06f9de874473eaf1d36b3a41911ac072b7826e6acea3d8425dc271833dba2ec17d1a270e49becbf21330ba2f0edc4b05f4df01623f3c82246ae23ea2c022434ef09611aa19ba35c3ecbad965af3ad9bc6c9b0d3b059c239ffbf9272d0150c151b4510d659cbd0e4a9c32945c612681b70ee4dcbeefeacde630b127115fd9af16cef4afefe611c9dfcc63e6833bf4dab79a7e1ae3f70321429557ab9da48bf93647830b5eb5780f23476d3d4d06a39ae532da5b2f30f151587eb5df19ec1acf099e1ac506e071eb52c3c3cc88ccf6622b2913acf07f1b772b5012e39173211e51773f3eb42d667fff1d902c5c87bd507837b3fd993e70ac9706a0");
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x03e1c4bb705c871bf9bfda3e74b7f8f86bff267993c215a89d5795e3708e5e1f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("zencash.io", "testnet-zen.zencash.io"));
        vSeeds.push_back(CDNSSeedData("zdeveloper.org", "testnet-zen.zdeveloper.org"));
        vSeeds.push_back(CDNSSeedData("rotorproject.org", "testnet-zen.rotorproject.org"));

        // guarantees the first 2 characters, when base58 encoded, are "tn"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x26};
        // guarantees the first 2 characters, when base58 encoded, are "t4"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBC};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Allocation script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t284JhyS8LGM72Tx1porSqwrcq3CejthP1p", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
            "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h", "t3J8d43gMGysce5VsMkFWxVVyQ6C2KfaR7h",
        };
        // Allocation script expects a vector of 2-of-3 multisig addresses
        vDAOAddress = {
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
            "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q", "t34Ut6vx3XHac87aXRVdT7PwS2Cj9sz1s9Q",
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
        assert(vDAOAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0x2f;
        pchMessageStart[1] = 0x54;
        pchMessageStart[2] = 0xcc;
        pchMessageStart[3] = 0x9d;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        //genesis.nTime = 1482971059;
        //genesis.nBits = 0x200f0f0f;
        //genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        //genesis.nSolution = ParseHex("05ffd6ad016271ade20cfce093959c3addb2079629f9f123c52ef920caa316531af5af3f");
        //consensus.hashGenesisBlock = genesis.GetHash();

        // start genesis builder
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.nTime = 1494524072;
        genesis.nBits = 0x200f0f0f;
        genesis.nNonce   = uint256S("0x00000000000000000000000000000000000000000000000000000000000000fd");
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        nDefaultPort = 18133;

        genesis.nTime    = 1478403829;
        genesis.nBits    = 0x207fffff;
        genesis.nNonce   = uint256S("0x00000000000000000000000000000000000000000000000000000000000000fd");

        arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);

        while(true){
            genesis.nNonce =  ArithToUint256(UintToArith256(genesis.nNonce) + 1);
            // Hash state
            crypto_generichash_blake2b_state state;
            EhInitialiseState(nEquihashN, nEquihashK, state);

            // I = the block header minus nonce and solution.
            CEquihashInput I{genesis};
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << I;

            // H(I||...
            crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

            // H(I||V||...
            crypto_generichash_blake2b_state curr_state;
            curr_state = state;
            crypto_generichash_blake2b_update(&curr_state,
                                              genesis.nNonce.begin(),
                                              genesis.nNonce.size());

            // (x_1, x_2, ...) = A(I, V, n, k)
            LogPrint("pow", "Running Equihash solver \"%s\" with nNonce = %s\n",
                     "tronce", genesis.nNonce.ToString());

            MyNamespace::equi eq(1);

            eq.setstate(&curr_state);

            // Intialization done, start algo driver.
            eq.digit0(0);
            eq.xfull = eq.bfull = eq.hfull = 0;
            eq.showbsizes(0);
            for (MyNamespace::u32 r = 1; r < WK; r++) {
                (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                eq.xfull = eq.bfull = eq.hfull = 0;
                eq.showbsizes(r);
            }
            eq.digitK(0);

            // Convert solution indices to byte array (decompress) and pass it to validBlock method.
            for (size_t s = 0; s < eq.nsols; s++) {
                LogPrint("pow", "Checking solution %d\n", s+1);
                std::vector<eh_index> index_vector(MyNamespace::PROOFSIZE);
                for (size_t i = 0; i < MyNamespace::PROOFSIZE; i++) {
                    index_vector[i] = eq.sols[s][i];
                }
                std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

                struct bin2hex_str
                {
                    std::ostream& os;
                    bin2hex_str(std::ostream& os) : os(os) {}
                    void operator ()(unsigned char ch)
                    {
                        os << std::hex
                        << std::setw(2)
                        << static_cast<int>(ch);
                    }
                };

                genesis.nSolution = sol_char;

                std::ostringstream oss;
                oss << std::setfill('0');
                std::for_each(sol_char.begin(), sol_char.end(), bin2hex_str(oss));
                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << oss.str() << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;

                printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                printf("block.nNonce = %s\n", genesis.nNonce.ToString().c_str());
                printf("hashTarget = %s\n", hashTarget.ToString().c_str());


                if (UintToArith256(genesis.GetHash()) < hashTarget) {
                    printf("GOT HERE");
                    std::ostringstream oss;
                    oss << std::setfill('0');
                    std::for_each(sol_char.begin(), sol_char.end(), bin2hex_str(oss));
                    std::cout << std::endl;
                    std::cout << std::endl;
                    std::cout << oss.str() << std::endl;
                    std::cout << std::endl;
                    std::cout << std::endl;
                    break;
                }
            }

        }

        genesis.nSolution = ParseHex("0046c7e5a8e651d74ac6c0dcb7b48b6d12a7af4dc4131cdeebf01a161dbf55c89e22e6e4da440a7e59e20b82caf6b714930ad33d62bc6951e54e948538a3790ddbb406164681d6f45084f0eebb3126100074d82d052269c80d01f8b2b5eb08e678720ca2f1965f807345c072bf1913051525f7b7dff2eab452609d7fd3b212af8ad17996f0b99aea81f61d5ca91cab65e859a02d458b98e856d24d6855d51f1a7e8fb9905498afba006aaa9c630bbb9ff9a11495e7672eb9fc7f1151a814c11b8f7829662778e1f1a5089e3cd15122aeb8e20f8f75aa1888dd1173343b0389e6390ed7363cc03238d063c516d3100db7bab6a2f9744b6346659d1359022f5ccf216495cfc4bd269702e22a8750e6bdf85430652c5cc4a61041b9eae93cfb4fb9a6706854c24d0463f32963a32d9790cd615ee87b4bb1d4031ad9ac3c78ef21de73de33a75cb646c84639ba8d06dbacb3032099dbb3c131786a0bab7cac7fb9e3b32c1f1dea24ab771c9056252b57d175f71bd928f59610dd898c1a953b32bd89e7252cbe07df48c72f92684dfdc4014445131ac99b7511fe10b551c5796e11fd2d10d4bd0e37159ff1b207b9b45415c95b7c4c0dcd8f5bda4032071e9b2d6041b75330f34228eee051b1a5b3e49440cf56e138a88bef5449e4560de8174d42dd5f96fe52b8241c602a68e3695d593fd9edaeeb92b57e709a07ea2c617d47d8ff6e4930ebbda42a9063fa47af371da2eaf580511242961c0436517fc23931adaeae40173f30e125870af59a512291876926623d81f3d1502bc02d8a6f4d8939850dc4e3faed27d6692633f3b213141d955af0fc598ae7f2bd0521077f6c0f7bcd0c32295cf8fcd33f6d6826c44751f07412d8d859f7262720d43ff8d3ace3239854132a52eb5ae882f7dafe6310079760edc87bf646fa0f4d5e87068406f85034008221a145e60635a5ff4295fd6c398e23b19ed6b10600099f505e79f1d8bdc0b5447400306eba56a27b0a6273470602f0769e2fc2d0af49d5513f3576b53f22fa5dfc387767c5d308f902b2574c6eedec9ff94516d121fdd88c3e4e632c952a28750f71603e78d04c8947ae9a8be476b1a02868a7ecf39216e0899d9aae2370c9f3d27b4677f5cdb6abc5e94a91d41750974133bfa6b76e1c2ec7ae3fe48ea3373682d3659786420498d05288afc6d9bcba3740ce5a114b0903fc26ce1ae884f99f504ec4c222a281e214a2ae76fd190d831e5bb173e1a51f73ccc2551d2f7b04217224fba149268604ad7cade90df2c255ec454c4de62bdbb37a8416499f71adc917bfa2e634001fab0811e2adb44e913c361df70e1a307f8c52978c2b5b04e20d8755fc9a1d9dff7e48cd94b9c629e3b41b2e39de2cf1b4e39545165fcb34dd63f9394215fb0a3e0289cc21fad11905551846dec209ce132c126bced5bad5a01ad802fa0625a69800c3e6b3f9fd00a5b1a13bbccd7af9d08a186f2fd5b63ae597d991d4acb52d1a15a0d5be201b7d1327c57021bc33e5cabcbc61691a2f3bee9d656a06b6337c352235575377b4bc91af6eb19898fef2772af4ed97e512817ec68c52bdf3fab26b3bde7f3f9d349f1646c91cec27dfea16888fe40e1a7e729f4597403c6757f71149fed44c58535cc532923e439f81a80646a78b0c4613706fa4f6f5d8e6062ec42857df1b1fa0c380dc1d78974d1ea34786bd34063be6fb900c066674f6ef929959ed1160de442ffab61c7fb2cebd1e97e9b9b3564f82f961874a8445d3967502560ec9071e349f48421863e80b3359e49cb53a734c1866a6326c7fb9c5f1fe89c0927624ddd4229dc68e745edc0af2f6eee902c5d32f9e038f04a4c99e0a8abcaa6e0efc021039d520a31dc4399283d4ff87a7aadead2b");

        // end genesis builder



        assert(consensus.hashGenesisBlock == uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

        // Allocation script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t33aqg8xUURVQVgyutfGzHAmn6nnkhFpZpL" };
	vDAOAddress = { "t3ELub7Kz4kTHomWYdhqb4Xy2D9cWvpYnQ6" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
        assert(vDAOAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;

    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
