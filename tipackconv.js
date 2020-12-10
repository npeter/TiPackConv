// (c) npeter 2020-11-20
// 
// Convert TI Packet Sniffer data file (*.psd) into a format which can be imported into Excel for analysis
//
// Rev 1.0.0 - first release


//const { timeStamp } = require('console')
//var remote = require('remote')
//var dialog = remote.require('dialog')

const version = '1.0.0'

let SPDU = {    // Sniffer protocol data unit
    hdr: {
        SPDUInformation: null,
        SPDUInformationRaw: null,
        SPDUNumber: null, 
        timeStampUs: null,
        timeStampS: null,
        timeDeltaS: null,
        SPDULength: null     
    },
    fdr: {
        payload: [null]            
    },
    status: {
        rssi: null,         // Byte1
        devInfo: null,      // Byte2 0-7
        crcOk: null,        // Byte2 7
        msg:    null
    }
}

let MPDU = {    // MAC layer protocol data unit
    hdr: {
        type: null,
        length: null,
        frameControl: null,
        frameControlRaw: null,
        security:   null,
        sequenceNumber: null,
        destPANid:  null,
        destAddr: null,
        srcPANid:   null,
        srcAddr:    null,
    },
    fdr:{
        payload: [null],
        checkSum:  null        
    }
}

let NPDU = {    // network layer protocol data unit
    hdr: {                              // octets
        fctrl: {                        // 2
            raw:                null,   
            frameType:          null,
            protocolVersion:    null,
            discoverRoute:      null,
            multicastFlag:      null,
            security:           null,
            srcRoute:           null,
            destIEEEaddr:       null,   
            srcIEEEaddr:        null,
            endDeviceIndicator: null
        },
        destAddr:   null,               // 2
        srcAddr: null,                  // 2
        brodcastRadius: null,           // 1
        broadcastSeqNum: null,          // 1
        destIEEEaddr: null,             // 0/8
        srcIEEEaddr: null,              // 0/8
        multicastControl: null, 	    // 0/1
        sourceRouteSubframe: null       // var
    }, 
    fdr: {
        payload: [null]                 // var        
    },
    cmd: {
        cmdIdentifier: null,             // 1
        cmdPayload: null,                // var
        type: null  
    }
}

let APDU = {    // application layer data unit
    hdr: {                          // octets
         frameControl: {            // 2
             
            raw: null,
            frameType: null,
            deliveryMode: null,
            ackFormat: null,
            security: null,
            ackReq: null,
            extendedHdr: null
        }, 
        frameControlRaw:    null,   // -
        destEndpoint:       null,   // 0/1
        groupAddr:          null,   // 0/2
        clusterIdentifier:  null,   // 0/2
        profilIdentifier:   null,   // 0/2
        srcEndpoint:        null,   // 0/1
        apsCounter:         null,   // 1
        extendedHdr:        null    // 0/var
    },
    fdr: {
        apsCmdIdentifier: null,
        payload: [null]              // var
    },
    cmd: {
        type: null
    }
}

const BIT_00 = 0b0000000000000001
const BIT_01 = 0b0000000000000010
const BIT_02 = 0b0000000000000100
const BIT_03 = 0b0000000000001000
const BIT_04 = 0b0000000000010000
const BIT_05 = 0b0000000000100000
const BIT_06 = 0b0000000001000000
const BIT_07 = 0b0000000010000000
const BIT_08 = 0b0000000100000000
const BIT_09 = 0b0000001000000000
const BIT_10 = 0b0000010000000000
const BIT_11 = 0b0000100000000000
const BIT_12 = 0b0001000000000000
const BIT_13 = 0b0010000000000000
const BIT_14 = 0b0100000000000000
const BIT_15 = 0b1000000000000000

// SPDU information coding
const SPDU_INFORMATION_LENGTH_INCLUDING_FRAME_STATUS_BYTE_MSK = 0b00001
const SPDU_INFORMATION_CORRELATION_USED_MSK                   = 0b00010
const SPDU_INFORMATION_INCOMPLETE_SPDU_MSK                    = 0b00100
const SPDU_INFORMATION_GENERIC_SNIFFER_IS_USED_MSK            = 0b10000

// SPDU status byte 2 CRC OK
const SPDU_STATUS_BYTE2_CRC_MSK = BIT_07 

// MPDU coding
const MPDU_CONTROL_FIELD_MPDU_TYPE_BEACON                 = 0
const MPDU_CONTROL_FIELD_MPDU_TYPE_DATA                   = 1
const MPDU_CONTROL_FIELD_MPDU_TYPE_ACKNOWLEDGEMENT        = 2
const MPDU_CONTROL_FIELD_MPDU_TYPE_MPDU                    = 3

const MPDU_CONTROL_FIELD_MPDU_TYPE_MSK         = BIT_00 | BIT_01 | BIT_02
const MPDU_CONTROL_FIELD_SECURITY_ENABLED_MSK  = BIT_03
const MPDU_CONTROL_FIELD_MPDU_PENDING_MSK      = BIT_04
const MPDU_CONTROL_FIELD_ACK_REQUEST_MSK       = BIT_05
const MPDU_CONTROL_FIELD_PAN_COMPR_MSK         = BIT_06
const MPDU_CONTROL_FIELD_DEST_ADDR_MODE_MSK    = BIT_10 | BIT_11 
const MPDU_CONTROL_FIELD_SRC_ADDR_MODE_MSK     = BIT_14 | BIT_15

const MPDU_CONTROL_FIELD_DEST_ADDR_MODE_NOT_PRESENT     = (0<<10)
const MPDU_CONTROL_FIELD_DEST_ADDR_MODE_RESERVED        = (1<<10)
const MPDU_CONTROL_FIELD_DEST_ADDR_MODE_SHORT_ADDR      = (2<<10)
const MPDU_CONTROL_FIELD_DEST_ADDR_MODE_EXTENTED_ADDR   = (3<<10)

const MPDU_CONTROL_FIELD_SRC_ADDR_MODE_NOT_PRESENT     = (0<<14)
const MPDU_CONTROL_FIELD_SRC_ADDR_MODE_RESERVED        = (1<<14)
const MPDU_CONTROL_FIELD_SRC_ADDR_MODE_SHORT_ADDR      = (2<<14)
const MPDU_CONTROL_FIELD_SRC_ADDR_MODE_EXTENTED_ADDR   = (3<<14)

// NWK coding
const NPDU_CONTROL_NPDU_TYPE_MSK             = BIT_00 | BIT_01
const NPDU_CONTROL_PROTOCOL_VERSION_MSK      = BIT_02 | BIT_03 | BIT_04 | BIT_05
const NPDU_CONTROL_DISCOVER_ROUTE_MSK        = BIT_06 | BIT_07
const NPDU_CONTROL_MULTICAST_FLAG_MSK        = BIT_08
const NPDU_CONTROL_SECURITY_MSK              = BIT_09
const NPDU_CONTROL_SRC_ROUTE_MSK             = BIT_10
const NPDU_CONTROL_DEST_IEEEADDR_MSK         = BIT_11
const NPDU_CONTROL_SRC_IEEEADDR_MSK          = BIT_12
const NPDU_CONTROL_END_DEVICE_INITIATOR_MSK  = BIT_13
const NPDU_CONTROL_RESERVED_MSK              = BIT_14 | BIT_15 

const NPDU_CONTROL_NPDU_TYPE_DATA           = (0<<0)
const NPDU_CONTROL_NPDU_TYPE_NPDU_COMMAND    = (1<<0)
const NPDU_CONTROL_NPDU_TYPE_INTER_PAN      = (3<<0)

const NPDU_CONTROL_NPDU_PROTOCOL_VERSION_RSHIFT = 2

const NPDU_CONTROL_DISCOVER_ROUTE_SUPPRESS   = (0<<6)
const NPDU_CONTROL_DISCOVER_ROUTE_ENABLE     = (1<<6)

const NPDU_COMMAND_ROUTE_REQUEST                 = 0x01    
const NPDU_COMMAND_ROUTE_REPLAY                  = 0x02
const NPDU_COMMAND_NW_STATUS                     = 0x03
const NPDU_COMMAND_LEAVE                         = 0x04
const NPDU_COMMAND_ROUTE_SPDU                    = 0x05
const NPDU_COMMAND_REJOIN_REQUEST                = 0x06
const NPDU_COMMAND_REJOIN_RESPONSE               = 0x07
const NPDU_COMMAND_LINK_STATUS                   = 0x08
const NPDU_COMMAND_NW_REPORT                     = 0x09
const NPDU_COMMAND_NW_UPDATE                     = 0x0a
const NPDU_COMMAND_END_DEVICE_TIMEOUT_REQUEST    = 0x0b
const NPDU_COMMAND_END_DEVICE_TIMEOUT_RESPONSE   = 0x0c

// APDU coding
const APDU_FRAME_TYPE_MSK           = BIT_00 | BIT_01
const APDU_DELIVERY_MODE_MSK        = BIT_02 | BIT_03
const APDU_ACK_FORMAT_MSK           = BIT_04
const APDU_SEQURITY_MSK             = BIT_05
const APDU_ACK_REQUEST_MSK          = BIT_06
const APDU_EXTENDET_HDR_PRESENT_MSK = BIT_07

const APDU_FRAME_TYPE_DATA      = (0<<0)
const APDU_FRAME_TYPE_CMD       = (1<<0)
const APDU_FRAME_TYPE_ACK       = (2<<0)
const APDU_FRAME_TYPE_INTER_PAN = (3<<0)

// Delivery mode subfield 2.2.5.1.1.2
const APDU_DELIVERY_MODE_NORMAL_UNICAST   = (0<<2)
const APDU_DELIVERY_MODE_BROADCAST        = (2<<2)
const APDU_DELIVERY_MODE_GROUP_ADDRESSING = (3<<2)

const APDU_CMD_IDENT_ROUTE_REQ              = 0x01
const APDU_CMD_IDENT_ROUTE_RPL              = 0x02
const APDU_CMD_IDENT_NW_STATUS              = 0x03
const APDU_CMD_IDENT_LEAVE                  = 0x04
const APDU_CMD_IDENT_ROUTE_RECORD           = 0x05
const APDU_CMD_IDENT_REJOIN_REQ             = 0x06
const APDU_CMD_IDENT_REJOIN_RSP             = 0x07
const APDU_CMD_IDENT_LINK_STATUS            = 0x08
const APDU_CMD_IDENT_NW_REPORT              = 0x09
const APDU_CMD_IDENT_NW_UPDATE              = 0x0a
const APDU_CMD_IDENT_END_DEVICE_TOUT_REQ    = 0x0b
const APDU_CMD_IDENT_END_DEVICE_TOUT_RSP    = 0x0c

/*


*/
function tiPackConv() {
   const path = require('path')
   const commander = require('commander')
   const program = new commander.Command()
  
   program
    .requiredOption('-i, --infile <infile>,  ', 'sniff input file')
    .option('-o, --outfile <outfile, ', 'sniff output file')
    .option('-v, --verbose, ', 'verbose')
    .version(version)

    program.parse(process.argv)

    //console.log('program.infile :' + program.infile)
    //console.log('program.outfile:' + program.outfile)
    //console.log('program.verbose:' + program.verbose)

    let fnameIn  = null
    let fnameOut = null
    let verbose  = false
 
    if (program.infile != undefined) {
        fnameIn = program.infile 
        pathObj = path.parse(program.infile)
        if (pathObj.ext == '.psd') {
            if (program.outfile != undefined) {
                fnameOut = program.outfile 
            }
            else {
                if (pathObj.dir.length > 0) {
                    fnameOut = pathObj.dir + '/' + pathObj.name + '.txt'
                }
                else {
                    fnameOut = pathObj.name + '.txt'
                }
                
            }            
        }
        else {
            console.log('+++ err: wrong  infile extension:' + pathObj.ext)
        }
 
    }
    else {
        console.log('+++ err: infile name missed' )
    }

    verbose = (program.verbose != undefined) ? true : false

    //console.log('fnameIn : ' + fnameIn )
    //console.log('fnameOut: ' + fnameOut)
    //console.log('verbose : ' + verbose )

    if ((fnameIn != null) & (fnameOut != 0)) {
        doTiPackConv(fnameIn, fnameOut, verbose)
    }
}

// test only
function tiPackConvTest() {

    const fnameLst = 
    [   
        'QS1_2020_12_08_a', /*
        'QS1_2020_12_03_b', /*
        'QS1_2020_12_03_a', 
        'QS1_2020_12_2_a_low_power' 
        'tst_2020_12_2_0111', 
        'test_01112020_12_01', 
        'MPPT_0001',
        'MPPT_0010',
        'MPPT_0100',
        'MPPT_1000',
        'MPPT_1011',
        'pair_QS1_TI_ZBPro_2020-11-03',
        'pair_YC600_TI_ZBPro' */
    ]

    const fnameExtIn    = 'psd'
    const fnameExtOut   = 'txt'
    const pathIn        = 'E:\\Projekte\\ghJS\\TiPackConv\\Sniff\\'
    const pathOut       = 'E:\\Projekte\\ghJS\\TiPackConv\\Sniff\\'

    fnameLst.forEach(fname => {
        let fnameIn   = pathIn  + fname + '.' + fnameExtIn
        let fnameOut  = pathOut + fname + '.' + fnameExtOut
        doTiPackConv(fnameIn, fnameOut, true)          
    })
}



/*
    doTiPackConv    
    Todo

    @sniffIn
    input file TI Packet Sniffer format
    @sniffOut
    output file to be imported into excel (with space as separator)
    @verbose - console output
     
*/
function doTiPackConv(sniffIn, sniffOut, verbose) {

    verbose =  (verbose == undefined | verbose == null) ? false : verbose

    let frameCnt = 0
    const basename = require('path').win32.basename(sniffIn, '.psd')

    //let fsr = require('fs')
    let buffer = require('fs').readFileSync(sniffIn, (err, file) => {
        throw err
    })

    let fsw = require('fs')

    // output header line 1
    fsw.writeFileSync(sniffOut, sniffIn + '\n', function (err, file) {
        if (err) throw err
        console.log('writeFileSync()')
    })

    // output header line 2
    fsw.appendFileSync(sniffOut, ' ' + outSpduHdr(1) + outMpduHdr(1) + outNpduHdr(1) + outApduHdr(1) + '\n', function (err, file) {
        if (err) throw err
        console.log('writeFileSync()')
    })

    
    
    // output header line 3
    fsw.appendFileSync(sniffOut, basename + ' ' + outSpduHdr(2) + outMpduHdr(2) + outNpduHdr(2) + outApduHdr(2) + '\n', (err) => {
        if (err) throw err
    })


    let spdu    = SPDU
    let mpdu    = MPDU     
    let npdu    = NPDU
    let apdu    = APDU

    let bufferIdx = 0    
    let spduTimeStampS = 0

    // 
    do {

        clearXpdu(spdu)
        clearXpdu(mpdu)
        clearXpdu(npdu)
        clearXpdu(apdu)
        
        let errorMsg = null

        spdu.fdr.payload = []
        mpdu.fdr.payload = []
        npdu.fdr.payload = []
        apdu.fdr.payload = []

        let sidx  = bufferIdx
        bufferIdx += 151        // prepare for next spdu
 
        spdu.hdr.SPDUInformationRaw = raw2Int(buffer.slice(sidx, sidx+1));  
        spdu.hdr.SPDUInformation    = raw2Int(buffer.slice(sidx, sidx+1));        sidx += 1
        spdu.hdr.SPDUNumber         = raw2Int(buffer.slice(sidx, sidx+4));        sidx += 4
        spdu.hdr.timeStampUs        = raw2Int(buffer.slice(sidx, sidx+8)) / 32;   sidx += 8
        spdu.hdr.timeStampS         = Math.floor(spdu.hdr.timeStampUs / 1000000) 
        spdu.hdr.timeDeltaS         = spdu.hdr.timeStampS - spduTimeStampS
        spduTimeStampS              = spdu.hdr.timeStampS
        spdu.hdr.SPDULength         = raw2Int(buffer.slice(sidx, sidx+2));   sidx += 2

        if ( spdu.hdr.SPDUInformationRaw & SPDU_INFORMATION_LENGTH_INCLUDING_FRAME_STATUS_BYTE_MSK ) {
            spdu.hdr.SPDULength--  
        }

        spdu.fdr.payload  = buffer.slice(sidx, sidx+spdu.hdr.SPDULength-1);  sidx += spdu.hdr.SPDULength-1

        spdu.status.rssi     = raw2Int(buffer.slice(sidx, sidx+1));  sidx += 1
        spdu.status.devInfo  = raw2Int(buffer.slice(sidx, sidx+1));  sidx += 1
        spdu.status.crcOk    = (spdu.status.devInfo & SPDU_STATUS_BYTE2_CRC_MSK) ? true : false

        //console.log(buffer.slice(bufferIdx, bufferIdx+151))    
     
        if (spdu.status.crcOk) {

            // MPDU
            let midx = 0
            mpdu.hdr.length          =        raw2Int(spdu.fdr.payload.slice(midx, midx+1)).toString();   midx += 1
            mpdu.hdr.frameControlRaw =        raw2Int(spdu.fdr.payload.slice(midx, midx+2)).toString();  
            mpdu.hdr.frameControl    = 'bx' + raw2Int(spdu.fdr.payload.slice(midx, midx+2)).toString(2);  midx += 2
            mpdu.hdr.sequenceNumber  =        raw2Int(spdu.fdr.payload.slice(midx, midx+1)).toString();   midx += 1
        
            // mpdu frame type, dest addressing mode, src addressing mode
            const mpduFrameControlFieldType     = mpdu.hdr.frameControlRaw & MPDU_CONTROL_FIELD_MPDU_TYPE_MSK
            const mpduFrameControlFieldDestAddr = mpdu.hdr.frameControlRaw & MPDU_CONTROL_FIELD_DEST_ADDR_MODE_MSK
            const mpduFrameControlFieldSrcAddr  = mpdu.hdr.frameControlRaw & MPDU_CONTROL_FIELD_SRC_ADDR_MODE_MSK

            // dest pan 0/2
            if (mpduFrameControlFieldDestAddr) {
                mpdu.hdr.destPANid  = raw2hex(spdu.fdr.payload.slice(midx, midx+2), 4); midx += 2      
            }

            // destAddr 0/2/8
            if (mpduFrameControlFieldDestAddr) {
                if (mpduFrameControlFieldDestAddr == MPDU_CONTROL_FIELD_DEST_ADDR_MODE_SHORT_ADDR) {
                    mpdu.hdr.destAddr   = raw2hex(spdu.fdr.payload.slice(midx, midx+2), 4); midx += 2  
                }
                else if (mpduFrameControlFieldDestAddr == MPDU_CONTROL_FIELD_DEST_ADDR_MODE_EXTENTED_ADDR) {
                    mpdu.hdr.destAddr   = raw2hex(spdu.fdr.payload.slice(midx, midx+8), 16); midx += 8  
                }
                else {
                    mpdu.hdr.destAddr = 'mpduFrameControlFieldDestAddr_RESERVED'   
                }            
            }

            // srcPan 0/2
            if (mpduFrameControlFieldSrcAddr & !(mpdu.hdr.frameControlRaw & MPDU_CONTROL_FIELD_PAN_COMPR_MSK)) {
                    mpdu.hdr.srcPANid = raw2hex(spdu.fdr.payload.slice(midx, midx+2), 4); midx += 2  
            }


            // srcAddr 0/2/8
            if (mpduFrameControlFieldSrcAddr) {
                if (mpduFrameControlFieldSrcAddr == MPDU_CONTROL_FIELD_SRC_ADDR_MODE_SHORT_ADDR) {
                    mpdu.hdr.srcAddr   = raw2hex(spdu.fdr.payload.slice(midx, midx+2), 4); midx += 2  
                }
                else if (mpduFrameControlFieldSrcAddr == MPDU_CONTROL_FIELD_SRC_ADDR_MODE_EXTENTED_ADDR) {
                    mpdu.hdr.srcAddr   = raw2hex(spdu.fdr.payload.slice(midx, midx+8), 16); midx += 8  
                }
                else {
                    mpdu.hdr.destAddr = 'mpduFrameControlFieldDestAddr_RESERVED'   
                }            
            }

            // auxiliary security header field 7.2.1.7
            if (mpdu.hdr.frameControlRaw & MPDU_CONTROL_FIELD_SECURITY_ENABLED_MSK) {
                    mpdu.hdr.security  = 'SECURITY_NOT_SUPPORTED'               
            }
            else {
                    mpdu.hdr.security = '0'
            }


            // Beacon Frame format    
            if (  mpduFrameControlFieldType ==  MPDU_CONTROL_FIELD_MPDU_TYPE_BEACON) {
                mpdu.hdr.type = 'BEACON'
            }

            // Data Frame format
            else if (  mpduFrameControlFieldType ==  MPDU_CONTROL_FIELD_MPDU_TYPE_DATA) {
                // todo short addressing mode
                mpdu.hdr.type       = 'DATA'
                mpdu.fdr.payload           = spdu.fdr.payload.slice(midx)
                // todo checksum

                // ==========================================================================================
                // NPDU decoding ============================================================================
                // ==========================================================================================            
                var nidx = 0
                npdu.hdr.fctrl.raw = raw2Int(mpdu.fdr.payload.slice(nidx, nidx+2)), nidx += 2
                
                // FrameControl Frame Type        
                const npduFrameType = npdu.hdr.fctrl.raw & NPDU_CONTROL_NPDU_TYPE_MSK

                if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_DATA)  {
                    npdu.hdr.fctrl.frameType = 'DATA'
                }
                else if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_NPDU_COMMAND) {
                    npdu.hdr.fctrl.frameType = 'CMD'
                    
                }
                else if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_INTER_PAN) {
                    npdu.hdr.fctrl.frameType = 'INTER_PAN'                
                }
                else {
                    npdu.hdr.fctrl.frameType = 'npdu.hdr.fctrl.frameType_INVALID_' + npduFrameType 
                }

                // FrameControl Protocol Version
                npdu.hdr.fctrl.protocolVersion = (npdu.hdr.fctrl.raw & NPDU_CONTROL_PROTOCOL_VERSION_MSK) >> NPDU_CONTROL_NPDU_PROTOCOL_VERSION_RSHIFT

                // FrameControl Discover Route
                if ( (npdu.hdr.fctrl.raw & NPDU_CONTROL_DISCOVER_ROUTE_MSK) == NPDU_CONTROL_DISCOVER_ROUTE_SUPPRESS)  {
                    npdu.hdr.fctrl.discoverRoute = 'SUPR'
                }
                else if ( (npdu.hdr.fctrl.raw & NPDU_CONTROL_DISCOVER_ROUTE_MSK) == NPDU_CONTROL_DISCOVER_ROUTE_ENABLE)  {
                    npdu.hdr.fctrl.discoverRoute = 'ROUTE_EN'            
                }
                else {
                    npdu.hdr.fctrl.discoverRoute = 'RESERVED_'+((npdu.hdr.fctrl.raw & NPDU_CONTROL_DISCOVER_ROUTE_MSK)>>6)      
                }

                // FrameControl etc
                npdu.hdr.fctrl.multicastFlag        = (npdu.hdr.fctrl.raw & NPDU_CONTROL_MULTICAST_FLAG_MSK         ) ? '1' : '0'
                npdu.hdr.fctrl.security             = (npdu.hdr.fctrl.raw & NPDU_CONTROL_SECURITY_MSK               ) ? '1' : '0'
                npdu.hdr.fctrl.srcRoute             = (npdu.hdr.fctrl.raw & NPDU_CONTROL_SRC_ROUTE_MSK              ) ? '1' : '0'
                npdu.hdr.fctrl.destIEEEaddr         = (npdu.hdr.fctrl.raw & NPDU_CONTROL_DEST_IEEEADDR_MSK          ) ? '1' : '0'
                npdu.hdr.fctrl.srcIEEEaddr          = (npdu.hdr.fctrl.raw & NPDU_CONTROL_SRC_IEEEADDR_MSK           ) ? '1' : '0'
                npdu.hdr.fctrl.endDeviceIndicator   = (npdu.hdr.fctrl.raw & NPDU_CONTROL_END_DEVICE_INITIATOR_MSK   ) ? '1' : '0'

                npdu.hdr.destAddr             = raw2hex(mpdu.fdr.payload.slice(nidx, nidx+2), 4); nidx += 2  
                npdu.hdr.srcAddr              = raw2hex(mpdu.fdr.payload.slice(nidx, nidx+2), 4); nidx += 2  
                npdu.hdr.brodcastRadius       = raw2Int(mpdu.fdr.payload.slice(nidx, nidx+1)).toString();   nidx += 1  
                npdu.hdr.broadcastSeqNum      = raw2Int(mpdu.fdr.payload.slice(nidx, nidx+1)).toString();   nidx += 1  

                if ( npdu.hdr.fctrl.raw & NPDU_CONTROL_DEST_IEEEADDR_MSK ) {
                    npdu.hdr.destIEEEaddr = raw2hex(mpdu.fdr.payload.slice(nidx, nidx+8), 16); nidx += 8  
                }
                
                if ( npdu.hdr.fctrl.raw & NPDU_CONTROL_SRC_IEEEADDR_MSK ) {
                    npdu.hdr.srcIEEEaddr = raw2hex(mpdu.fdr.payload.slice(nidx, nidx+8), 16); nidx += 8  
                }
                
                if ( npdu.hdr.fctrl.raw & NPDU_CONTROL_SRC_ROUTE_MSK ) {
                    
                    var sourceRoutelength = 1
                    npdu.hdr.sourceRouteSubframe = 'npdu.hdr.sourceRouteSubframe_NOT_SUPPORTED'
                }

                if ( npdu.hdr.fctrl.raw & NPDU_CONTROL_MULTICAST_FLAG_MSK ) {
                    npdu.hdr.multicastControl = raw2hex(mpdu.fdr.payload.slice(nidx, nidx+1), 2); nidx += 1  
                }
                
                npdu.fdr.payload = mpdu.fdr.payload.slice(nidx)

                if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_DATA) {
                    npdu.hdr.type = 'NPDU DATA'
                    
                    // =====================================================================================================
                    // APDU decoding =======================================================================================
                    // =====================================================================================================
                    var aidx = 0

                    apdu.hdr.frameControl.raw = raw2Int(npdu.fdr.payload.slice(aidx, aidx+1)); aidx += 1
    
                    const apduFrameType = apdu.hdr.frameControl.raw & APDU_FRAME_TYPE_MSK
                    if (apduFrameType == APDU_FRAME_TYPE_DATA) {
                        apdu.hdr.frameControl.frameType = 'DATA'
                    }
                    else if (apduFrameType == APDU_FRAME_TYPE_CMD) {
                        apdu.hdr.frameControl.frameType = 'CMD'
                    }
                    else if (apduFrameType == APDU_FRAME_TYPE_ACK) {
                        apdu.hdr.frameControl.frameType = 'ACK'
                    }
                    else if (apduFrameType == APDU_FRAME_TYPE_INTER_PAN) {
                        apdu.hdr.frameControl.frameType = 'INTER_PAN'
                    }
                    else {
                    throw 'invalid apdu.hdr.frameControl.frameType'
                    }

                    const apduDeliveryMode  = apdu.hdr.frameControl.raw & APDU_DELIVERY_MODE_MSK
                    if (apduDeliveryMode == APDU_DELIVERY_MODE_NORMAL_UNICAST) {
                        apdu.hdr.frameControl.deliveryMode = 'UNICAST'
                    }
                    else if (apduDeliveryMode == APDU_DELIVERY_MODE_BROADCAST) {
                        apdu.hdr.frameControl.deliveryMode = 'BROADCAST'
                    }
                    else if (apduDeliveryMode == APDU_DELIVERY_MODE_GROUP_ADDRESSING) {
                        apdu.hdr.frameControl.deliveryMode = 'GROUP'
                    }
                    else  {
                        apdu.hdr.frameControl.deliveryMode = 'INVALID_apduDeliveryMode_' + apduDeliveryMode
                    }

                    apdu.hdr.frameControl.ackFormat     = (apdu.hdr.frameControl.raw & APDU_ACK_FORMAT_MSK          ) ? '1' : '0' 
                    apdu.hdr.frameControl.security      = (apdu.hdr.frameControl.raw & APDU_SEQURITY_MSK            ) ? '1' : '0' 
                    apdu.hdr.frameControl.ackReq        = (apdu.hdr.frameControl.raw & APDU_ACK_REQUEST_MSK         ) ? '1' : '0' 
                    apdu.hdr.frameControl.extendedHdr   = (apdu.hdr.frameControl.raw & APDU_EXTENDET_HDR_PRESENT_MSK) ? '1' : '0' 

                    // Destination Endpoint 2.2.5.1.2
                    if ( (apduDeliveryMode == APDU_DELIVERY_MODE_NORMAL_UNICAST) | (apduDeliveryMode == APDU_DELIVERY_MODE_BROADCAST) ) {
                        apdu.hdr.destEndpoint = raw2hex(npdu.fdr.payload.slice(aidx, aidx+1), 2);  aidx += 1
                    }

                    // Group address field  2.2.5.1.
                    if ( apduDeliveryMode == APDU_DELIVERY_MODE_GROUP_ADDRESSING ) {
                        apdu.hdr.groupAddr = raw2hex(npdu.fdr.payload.slice(aidx, aidx+2), 4);  aidx += 2
                    }

                    
                    // Cluster identifier and profil identifier 2.2.5.1.4-5
                    if ( (apduFrameType == APDU_FRAME_TYPE_DATA) | (apduFrameType == APDU_FRAME_TYPE_ACK) ) {
                        apdu.hdr.clusterIdentifier = raw2hex(npdu.fdr.payload.slice(aidx, aidx+2), 4);  aidx += 2
                        apdu.hdr.profilIdentifier  = raw2hex(npdu.fdr.payload.slice(aidx, aidx+2), 4);  aidx += 2
                    }

                    // Source Endpoint Field 2.2.5.1.6 & 2.2.5.2.1
                    if (apduFrameType == APDU_FRAME_TYPE_DATA) {
                        apdu.hdr.srcEndpoint = raw2hex(npdu.fdr.payload.slice(aidx, aidx+1), 2);  aidx += 1
                    }
                    
                    // APS Counter 2.2.5.1.7
                    apdu.hdr.apsCounter = raw2Int(npdu.fdr.payload.slice(aidx, aidx+1)).toString();  aidx += 1
                    
                    // Extended Hdr 2.2.5.1.8
                    if (apdu.hdr.frameControlRaw & APDU_EXTENDET_HDR_PRESENT_MSK) {
                        // todo extended hdr
                        // extended framecontrol
                        // block number
                        // ACK bitfield
                    }

                    // APDU Data Frame Format 2.2.5.2.1
                    if (apduFrameType == APDU_FRAME_TYPE_DATA) {
                        apdu.fdr.payload          = npdu.fdr.payload.slice(aidx)
                        apdu.fdr.apsCmdIdentifier = null
                    }

                    // APDU Command Frames 3.4. 
                    else if (apduFrameType == APDU_FRAME_TYPE_CMD) {
                        apdu.fdr.apsCmdIdentifier = raw2Int(npdu.fdr.payload.slice(aidx, aidx+1)).toString();  aidx += 1    
                        apdu.fdr.payload = npdu.fdr.payload.slice(aidx)

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_ROUTE_REQ) {
                            apdu.cmd.type = 'AL CMD Route Request'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_ROUTE_RPL) {
                            apdu.cmd.type = 'AL CMD Route Replay'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_NW_STATUS) {
                            apdu.cmd.type = 'AL CMD Network Status'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_LEAVE) {
                            apdu.cmd.type = 'AL CMD Leave'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_ROUTE_RECORD) {
                            apdu.cmd.type = 'AL CMD Route Record'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_REJOIN_REQ) {
                            apdu.cmd.type = 'AL CMD Rejoin Request'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_REJOIN_RSP) {
                            apdu.cmd.type = 'AL CMD Rejoin Response'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_LINK_STATUS) {
                            apdu.cmd.type = 'AL CMD Link Status'
                        }

                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_NW_REPORT) {
                            apdu.cmd.type = 'AL CMD Route Request'
                        }
                        
                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_NW_REPORT) {
                            apdu.cmd.type = 'AL CMD Network Report'
                        }
                        
                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_END_DEVICE_TOUT_REQ) {
                            apdu.cmd.type = 'AL CMD End Device Timeout Request'
                        }
                        
                        if (apdu.fdr.apsCmdIdentifier == APDU_CMD_IDENT_END_DEVICE_TOUT_RSP) {
                            apdu.cmd.type = 'AL CMD End Device Timeout Response'
                        }
                        
                        else  {
                            apdu.cmd.type = 'RESERVED_' + apdu.fdr.apsCmdIdentifier
                        }

                    }

                    else if (apduFrameType == APDU_FRAME_TYPE_ACK) {
                        apdu.hdr.type = 'APDU Acknowledgement'
                    }

                    else if (apduFrameType == APDU_FRAME_TYPE_INTER_PAN) {
                        apdu.hdr.type = 'APDU Inter-PAN APS'

                    }

                    else {
                        apdu.hdr.type = 'INVALID_APDU_TYPE_' + apduFrameType
                    }
                }

                else if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_NPDU_COMMAND) {
                    npdu.hdr.type = 'CMD'              
                    npdu.cmd.cmdIdentifier = raw2Int(npdu.fdr.payload.slice(0,1))
                    npdu.cmd.cmdPayload    = npdu.fdr.payload.slice(1)

                    if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_ROUTE_REQUEST) {
                        npdu.cmd.type = 'ROUTE_REQ'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_ROUTE_REPLAY) {
                        npdu.cmd.type = 'ROUTE_REPL'
                    }
                    else    if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_NW_STATUS) {
                        npdu.cmd.type = 'NW_STATUS'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_LEAVE) {
                        npdu.cmd.type = 'LEAVE'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_ROUTE_SPDU) {
                        npdu.cmd.type = 'ROUTE_SPDU'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_REJOIN_REQUEST) {
                        npdu.cmd.type = 'REJOIN_REQ'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_REJOIN_RESPONSE) {
                        npdu.cmd.type = 'REJOIN_RESP'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_LINK_STATUS) {
                        npdu.cmd.type = 'LINK_STATUS'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_NW_REPORT) {
                        npdu.cmd.type = 'NW_REPORT'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_NW_UPDATE) {
                        npdu.cmd.type = 'NW_UPDATE'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_END_DEVICE_TIMEOUT_REQUEST) {
                        npdu.cmd.type = 'ED_TOUT_REQ'
                    }
                    else  if (npdu.cmd.cmdIdentifier & NPDU_COMMAND_END_DEVICE_TIMEOUT_RESPONSE) {
                        npdu.cmd.type = 'ED_TOUT_RESP'
                    }
                    else {
                        npdu.cmd.type = 'UNKNOWN: ' + npdu.cmd.cmdIdentifier
                    }
                }

                else if (npduFrameType == NPDU_CONTROL_NPDU_TYPE_INTER_PAN) {
                    npdu.hdr.type = 'INTER_PAN'
                }

                else {
                    npdu.hdr.type = 'npdu.hdr.type_RESERVED_' + npdu.hdr.type
                }

            }

            // Acknowledgement Frame format
            else if (  mpduFrameControlFieldType ==  MPDU_CONTROL_FIELD_MPDU_TYPE_ACKNOWLEDGEMENT) {
                mpdu.hdr.type = 'ACK'
            }

            // mpdu command Frame format
            else if (  mpduFrameControlFieldType ==  MPDU_CONTROL_FIELD_MPDU_TYPE_MPDU) {
                mpdu.hdr.type = 'CMD'
            }

            // reserved
            else {
                mpdu.hdr.type = 'RESERVED'
            }
    
    
        }

        else {  // if (!spdu.status.crcOk)
            spdu.status.msg = 'CRC_error'
            errorMsg        = 'CRC error at SPDU ' + spdu.hdr.SPDUNumber
        }

        //printSpdu(spdu)
        //printMpdu(mpdu)
        //printNpdu(npdu)
        //printApdu(apdu)
            
        var sSpdu = outSpdu(spdu)
        var sMpdu = outMpdu(mpdu) 
        var sNpdu = outNpdu(npdu) 
        var sApdu = outApdu(apdu)

        if ( (!verbose) & (errorMsg != null)) {
            console.log(errorMsg)
        }
        else if (verbose) {
            console.log(sSpdu + sMpdu + sNpdu + sApdu)      
        }           
    
        fsw.appendFileSync(sniffOut, basename + ' ' + sSpdu + sMpdu + sNpdu + sApdu + '\n', (err) => {
            if (err) throw err
        })
    
        frameCnt++

    } while( bufferIdx < buffer.length)
    
 
    console.log(sniffIn + ' -> ' + sniffOut + ' ' + frameCnt + ' frames processed')
}



/*
Output functions
*/

function printSpdu(spdu) {
    console.log('')
    console.log('+++ SPDU ++++++++++++++++++++++++++++++++++++++++++++++++++')
    console.log('spdu.hdr.SPDUInformation:' + spdu.hdr.SPDUInformation)
    console.log('spdu.hdr.SPDUNumber     :' + spdu.hdr.SPDUNumber)
    console.log('spdu.hdr.timeStampUs    :' + spdu.hdr.timeStampUs)
    console.log('spdu.hdr.timeStampS     :' + spdu.hdr.timeStampS)
    console.log('spdu.hdr.SPDULength     :' + spdu.hdr.SPDULength)
    console.log('spdu.fdr.payload.length :' + spdu.fdr.payload.length)        
    console.log('spdu.fdr.payload        :' + payload2HexString(spdu.fdr.payload))    
}

function outSpduHdr(line)
{
    let s = ''
    if (line == 1) {
        s += 'SPDU . . . . '
    }
    else {
        s += 'info no time delta length '
    }
    return s
}

function outSpdu(spdu) {
    let s = ''
    s += spdu.hdr.SPDUInformation   + ' '
    s += spdu.hdr.SPDUNumber        + ' '
    s += spdu.hdr.timeStampS        + ' '
    s += spdu.hdr.timeDeltaS        + ' '
    s += spdu.hdr.SPDULength        + ' '
    if (spdu.status.msg != null)  s += spdu.status.msg + ' '
    //s += 'info=' + spdu.fdr.payload.length   + ' '     
    //s += 'info=' + payload2HexString(spdu.fdr.payload) + ' '
    return s
}

function printMpdu(mpdu) {
    if (mpdu.hdr.length         != null) console.log('+++ %s ++++++++++++++++++++++++++++++++++++++++++++', mpdu.hdr.type)
    if (mpdu.hdr.length         != null) console.log('mpdu.hdr.length        :' + mpdu.hdr.length)
    if (mpdu.hdr.frameControl   != null) console.log('mpdu.hdr.frameControl  :' + mpdu.hdr.frameControl)
    if (mpdu.hdr.sequenceNumber != null) console.log('mpdu.hdr.sequenceNumber:' + mpdu.hdr.sequenceNumber)
    if (mpdu.hdr.destPANid      != null) console.log('mpdu.hdr.destPANid     :' + mpdu.hdr.destPANid)
    if (mpdu.hdr.destAddr       != null) console.log('mpdu.hdr.destAddr      :' + mpdu.hdr.destAddr)
    if (mpdu.hdr.srcAddr        != null) console.log('mpdu.hdr.srcAddr       :' + mpdu.hdr.srcAddr)
    if (mpdu.fdr.payload        != null) console.log('mpdu.fdr.payload.length:' + mpdu.fdr.payload.length)
    if (mpdu.fdr.payload        != null) console.log('mpdu.fdr.payload       :' + payload2HexString(mpdu.fdr.payload))
    if (mpdu.fdr.checkSum       != null) console.log('mpdu.fdr.checkSum      :' + mpdu.fdr.checkSum)
}

function outMpduHdr(line)
{
    let s = ''
    if (line == 1) {
        s += 'MPDU . . . . . . . . '
    }
    else {
        s += 'type length frameCtrl seqNo destPANid destAddr srcAddr length cs '
    }
    return s
}

function outMpdu(mpdu) {
    let s = '';
    if (mpdu.hdr.length != null) {

        if (mpdu.hdr.length         != null) s += mpdu.hdr.type + ' '
        else s += '. '
        if (mpdu.hdr.length         != null) s += mpdu.hdr.length + ' '
        else s += '. '
        if (mpdu.hdr.frameControl   != null) s += mpdu.hdr.frameControl + ' '
        else s += '. '
        if (mpdu.hdr.sequenceNumber != null) s += mpdu.hdr.sequenceNumber + ' '
        else s += '. '
        if (mpdu.hdr.destPANid      != null) s += mpdu.hdr.destPANid + ' '
        else s += '. '
        if (mpdu.hdr.destAddr       != null) s += mpdu.hdr.destAddr + ' '
        else s += '. '
        if (mpdu.hdr.srcAddr        != null) s += mpdu.hdr.srcAddr + ' '
        else s += '. '

        if (mpdu.fdr.payload        != null) s += mpdu.fdr.payload.length + ' '
        else s += '. '
        //if (mpdu.fdr.payload        != null) s += payload2HexString(mpdu.fdr.payload) + ' '
        //else s += '. '
        if (mpdu.fdr.checkSum       != null) s += mpdu.fdr.checkSum + ' '
        else s += '. '
    }
    else {
        s += '. . . . . . . '
    }
    return s
}

function printNpdu(npdu) {
    if (npdu.hdr.fctrl.frameType != null) console.log('+++ %s ++++++++++++++++++++++++++++++++++++++++++++++++++', npdu.hdr.fctrl.frameType)

    if (npdu.hdr.fctrl.protocolVersion      != null) console.log('npdu.hdr.fctrl.protocolVersion    :' + npdu.hdr.fctrl.protocolVersion)
    if (npdu.hdr.fctrl.discoverRoute        != null) console.log('npdu.hdr.fctrl.discoverRoute      :' + npdu.hdr.fctrl.discoverRoute)
    if (npdu.hdr.fctrl.multicastFlag        != null) console.log('npdu.hdr.fctrl.multicastFlag      :' + npdu.hdr.fctrl.multicastFlag)
    if (npdu.hdr.fctrl.security             != null) console.log('npdu.hdr.fctrl.security           :' + npdu.hdr.fctrl.security)
    if (npdu.hdr.fctrl.srcRoute             != null) console.log('npdu.hdr.fctrl.srcRoute           :' + npdu.hdr.fctrl.srcRoute)
    if (npdu.hdr.fctrl.destIEEEaddr         != null) console.log('npdu.hdr.fctrl.destIEEEaddr       :' + npdu.hdr.fctrl.destIEEEaddr)
    if (npdu.hdr.fctrl.srcIEEEaddr          != null) console.log('npdu.hdr.fctrl.srcIEEEaddr        :' + npdu.hdr.fctrl.srcIEEEaddr)
    if (npdu.hdr.fctrl.endDeviceIndicator   != null) console.log('npdu.hdr.fctrl.endDeviceIndicator :' + npdu.hdr.fctrl.endDeviceIndicator)
 
    if (npdu.hdr.destAddr                   != null) console.log('npdu.hdr.destAddr                 :' + npdu.hdr.destAddr)
    if (npdu.hdr.srcAddr                    != null) console.log('npdu.hdr.srcAddr                  :' + npdu.hdr.srcAddr)
    if (npdu.hdr.brodcastRadius             != null) console.log('npdu.hdr.brodcastRadius           :' + npdu.hdr.brodcastRadius)
    if (npdu.hdr.broadcastSeqNum            != null) console.log('npdu.hdr.broadcastSeqNum          :' + npdu.hdr.broadcastSeqNum)
    if (npdu.hdr.destIEEEaddr               != null) console.log('npdu.hdr.destIEEEaddr             :' + npdu.hdr.destIEEEaddr)
    if (npdu.hdr.srcIEEEaddr                != null) console.log('npdu.hdr.srcIEEEaddr              :' + npdu.hdr.srcIEEEaddr)
    if (npdu.hdr.multicastControl           != null) console.log('npdu.hdr.multicastControl         :' + npdu.hdr.multicastControl)
 
    if (npdu.fdr.payload.length             != null) console.log('npdu.fdr.payload.length           :' + npdu.fdr.payload.length)     
    if (npdu.fdr.payload.length             != null) console.log('npdu.fdr.payload                  :' + payload2HexString(npdu.fdr.payload))     
}

function outNpduHdr(line)
{
    let s = ''
    if (line == 1) {
        s += 'NPDU . . . . . . . . '
        s += '. . . . . . . . . . '
    }
    else {
        s += 'type cmd protVers discR mcFlag sec srcR destIEEEaddr srcIEEEaddr eDevInd '
        s += 'destAddr srcAddr bcRadius bcSeqNo destIEEEaddr srcIEEEadr mcCtrl length payload '
    }
    return s
}

function outNpdu(npdu) {
    let s = '';
    if (npdu.hdr.fctrl.frameType    != null) {

        if (npdu.hdr.fctrl.frameType            != null) s += npdu.hdr.fctrl.frameType + ' '
        else s += '. '
        
        if (npdu.cmd.type                       != null) s += npdu.cmd.type + ' '
        else s += '. '    

        if (npdu.hdr.fctrl.protocolVersion      != null) s += npdu.hdr.fctrl.protocolVersion + ' '
        else s += '. '
        if (npdu.hdr.fctrl.discoverRoute        != null) s += npdu.hdr.fctrl.discoverRoute + ' '
        else s += '. '
        if (npdu.hdr.fctrl.multicastFlag        != null) s += npdu.hdr.fctrl.multicastFlag + ' '
        else s += '. '
        if (npdu.hdr.fctrl.security             != null) s += npdu.hdr.fctrl.security + ' '
        else s += '. '
        if (npdu.hdr.fctrl.srcRoute             != null) s += npdu.hdr.fctrl.srcRoute + ' '
        else s += '. '
        if (npdu.hdr.fctrl.destIEEEaddr         != null) s += npdu.hdr.fctrl.destIEEEaddr + ' '
        else s += '. '
        if (npdu.hdr.fctrl.srcIEEEaddr          != null) s += npdu.hdr.fctrl.srcIEEEaddr + ' '
        else s += '. '
        if (npdu.hdr.fctrl.endDeviceIndicator   != null) s += npdu.hdr.fctrl.endDeviceIndicator + ' '
        else s += '. '
     
        if (npdu.hdr.destAddr                   != null) s += npdu.hdr.destAddr + ' '
        else s += '. '
        if (npdu.hdr.srcAddr                    != null) s += npdu.hdr.srcAddr + ' '
        else s += '. '
        if (npdu.hdr.brodcastRadius             != null) s += npdu.hdr.brodcastRadius + ' '
        else s += '. '
        if (npdu.hdr.broadcastSeqNum            != null) s += npdu.hdr.broadcastSeqNum + ' '
        else s += '. '
        if (npdu.hdr.destIEEEaddr               != null) s += npdu.hdr.destIEEEaddr + ' '
        else s += '. '
        if (npdu.hdr.srcIEEEaddr                != null) s += npdu.hdr.srcIEEEaddr + ' '
        else s += '. '
        if (npdu.hdr.multicastControl           != null) s += npdu.hdr.multicastControl + ' '
        else s += '. '
     
        if (npdu.fdr.payload.length             > 0) s += npdu.fdr.payload.length + ' '     
        else s += '. '
        
        if (npdu.fdr.payload.length             > 0) s += payload2HexString(npdu.fdr.payload, '.') + ' '  
        else s += '. '
        //s += '. '
    }
    else {
        '. . . . . . . . . . . . . . . . . . '
    }
    return s
}

function printApdu(apdu) {
    if (apdu.hdr.frameControl.frameType    != null) console.log('+++ %s ++++++++++++++++++++++++++++++++++++++++++++++++++', apdu.hdr.frameControl.frameType)
    if (apdu.hdr.frameControl.frameType    != null) console.log('apdu.hdr.frameControl.frameType   :' + apdu.hdr.frameControl.frameType)
    if (apdu.hdr.frameControl.deliveryMode != null) console.log('apdu.hdr.frameControl.deliveryMode:' + apdu.hdr.frameControl.deliveryMode)
    if (apdu.hdr.frameControl.ackFormat    != null) console.log('apdu.hdr.frameControl.ackFormat   :' + apdu.hdr.frameControl.ackFormat)
    if (apdu.hdr.frameControl.security     != null) console.log('apdu.hdr.frameControl.security    :' + apdu.hdr.frameControl.security)
    if (apdu.hdr.frameControl.ackReq       != null) console.log('apdu.hdr.frameControl.ackReq      :' + apdu.hdr.frameControl.ackReq)
    if (apdu.hdr.frameControl.extendedHdr  != null) console.log('apdu.hdr.frameControl.extendedHdr :' + apdu.hdr.frameControl.extendedHdr)

    if (apdu.hdr.destEndpoint      != null) console.log('apdu.hdr.destEndpoint              :' + apdu.hdr.destEndpoint)
    if (apdu.hdr.groupAddr         != null) console.log('apdu.hdr.groupAddr                 :' + apdu.hdr.groupAddr)
    if (apdu.hdr.clusterIdentifier != null) console.log('apdu.hdr.clusterIdentifier         :' + apdu.hdr.clusterIdentifier)
    if (apdu.hdr.profilIdentifier  != null) console.log('apdu.hdr.profilIdentifier          :' + apdu.hdr.profilIdentifier)
    if (apdu.hdr.srcEndpoint       != null) console.log('apdu.hdr.srcEndpoint               :' + apdu.hdr.srcEndpoint)
    if (apdu.hdr.apsCounter        != null) console.log('apdu.hdr.apsCounter                :' + apdu.hdr.apsCounter)
    if (apdu.fdr.apsCmdIdentifier  != null) console.log('apdu.fdr.apsCmdIdentifier          :' + apdu.fdr.apsCmdIdentifier)
 
    if (apdu.fdr.payload.length    > 0)     console.log('apdu.fdr.payload.length            :' + apdu.fdr.payload.length)     
    if (apdu.fdr.payload.length    > 0)     console.log('apdu.fdr.payload                   :' + payload2HexString(apdu.fdr.payload))     

    if (apdu.cmd.type              != null) console.log('apdu.cmd.type                      :' + apdu.cmd.type )    
}

function outApduHdr(line)
{
    let s = ''
    if (line == 1) {
        s += 'APDU . . . . .'
        s += '. . . . . . . . . . '
    }
    else {
        s += 'type dm ack sec ackR extHdr '
        s += 'destEP grpAddr clIdent profIdent srcEP Cnt cmdIdent cmdType length payload '
    }
    return s
}

function outApdu(apdu) {
    let s = '';
    if (apdu.hdr.frameControl.frameType    != null) {
        if (apdu.hdr.frameControl.frameType    != null) s += apdu.hdr.frameControl.frameType + ' '
        else s += '. '
        if (apdu.hdr.frameControl.deliveryMode != null) s += apdu.hdr.frameControl.deliveryMode + ' '
        else s += '. '
        if (apdu.hdr.frameControl.ackFormat    != null) s += apdu.hdr.frameControl.ackFormat + ' '
        else s += '. '
        if (apdu.hdr.frameControl.security     != null) s += apdu.hdr.frameControl.security + ' '
        else s += '. '
        if (apdu.hdr.frameControl.ackReq       != null) s += apdu.hdr.frameControl.ackReq + ' '
        else s += '. '
        if (apdu.hdr.frameControl.extendedHdr  != null) s += apdu.hdr.frameControl.extendedHdr + ' '
        else s += '. '

        if (apdu.hdr.destEndpoint      != null) s += apdu.hdr.destEndpoint + ' '
        else s += '. '
        if (apdu.hdr.groupAddr         != null) s += apdu.hdr.groupAddr + ' '
        else s += '. '
        if (apdu.hdr.clusterIdentifier != null) s += apdu.hdr.clusterIdentifier + ' '
        else s += '. '
        if (apdu.hdr.profilIdentifier  != null) s += apdu.hdr.profilIdentifier + ' '
        else s += '. '
        if (apdu.hdr.srcEndpoint       != null) s += apdu.hdr.srcEndpoint + ' '
        else s += '. '
        if (apdu.hdr.apsCounter        != null) s += apdu.hdr.apsCounter + ' '
        else s += '. '
        if (apdu.fdr.apsCmdIdentifier  != null) s += apdu.fdr.apsCmdIdentifier + ' '
        else s += '. '
        
        if (apdu.cmd.type              != null) s += apdu.cmd.type + ' ' 
        else s += '. '   
        
        if (apdu.fdr.payload.length    > 0)     s += apdu.fdr.payload.length + ' '     
        else s += '. '       
        if (apdu.fdr.payload.length    > 0)     s += payload2HexString(apdu.fdr.payload)   + ' '
        else s += '. '               
    }
    else {
        s += '. . . . . . . . . . . . . . . . '
    }
      
    return s
}



/*
Helpers 
*/
function raw2Int(raw) {
       
   var res = 0
    for (i = raw.length-1; i >= 0; i-- ) {
        res = res * 256 + raw[i]
    }
    return res
}

function raw2dec(raw) {
    return raw2Int(raw).toString() 
}

function raw2hex(raw, padding) {
     let hex = Number(raw2Int(raw)).toString(16)
    padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

    while (hex.length < padding) {
        hex = "0" + hex;
    }
    return '0x' + hex.toUpperCase();
}

function payload2HexString(payload,gap) {   
        if (gap == null | gap == undefined) {
            gap = ' '
        }
        return Array.from(payload, function(byte) {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join(gap)
}

function clearXpdu(xpdu) {
    if (Array.isArray(xpdu)) {
        xpdu.length = 0
        xpdu = []
    }
    for (let prop in xpdu) {
        if (typeof xpdu[prop] === 'object') {
            clearXpdu(xpdu[prop])                
        }
        else {
            xpdu[prop] = null                
        }
    }
}



tiPackConv()

module.exports.tiPackConv = tiPackConv

