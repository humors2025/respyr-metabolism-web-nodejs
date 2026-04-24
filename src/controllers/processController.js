const pool = require('../config/db');
const axios = require('axios');

exports.processData = async (req, res) => {
    try {
        const {
            testdata,
            subid,
            gender,
            height,
            age
        } = req.body;

        if (!testdata) {
            return res.status(400).json({ error: 'testdata is required' });
        }

        // Parse testdata
        const testdataexp = testdata.split('$');
        
        if (testdataexp.length < 17) {
            return res.status(400).json({ error: 'Invalid testdata format' });
        }
        
        const duration2 = testdataexp[16].split('H');
        const duration = duration2[0];
        const hwid2 = duration2[1].split('*');
        const hwid = hwid2[0];

        // Extract values from testdata
        const preval1820 = testdataexp[0];
        const raw1820 = testdataexp[1];
        const rawmain1820 = testdataexp[1];
        const finalraw1820 = testdataexp[2];
        const rawbmags = testdataexp[3];
        const finalags = testdataexp[4];
        const rawbase2600 = testdataexp[5];
        const rawbest2600 = testdataexp[6];
        const rawpress = testdataexp[7];
        const finalpress = testdataexp[8];
        const maxpress = testdataexp[9];
        const Base_hum = testdataexp[10];
        const Bm0_hum = testdataexp[11];
        const btemp = testdataexp[12];
        const bbtemp = testdataexp[13];
        const finaltemp = testdataexp[14];
        
        const name = subid || '';
        const login = subid || '';
        const gen = gender ? gender.toLowerCase() : '';
        const height_data = height || '';
        const age_data = age || '';

        // Set timezone and get current date (Asia/Kolkata)
        const now = new Date();
        const options = {
            timeZone: 'Asia/Kolkata',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        };
        
        const dateStr = now.toLocaleString('en-US', options);
        const [datePart, timePart] = dateStr.split(', ');
        const [month, day, year] = datePart.split('/');
        const date = `${month}/${day}/${year} ${timePart}`;
        
        const tmstamp = Math.floor(Date.now() / 1000);
        const dttestdate = date;

        // Get database connection
        const connection = await pool.getConnection();
        
        try {
            // Insert into param_life
            await connection.execute(
                "INSERT INTO `param_life` (`id`, `params`, `dttm`, `profileid`) VALUES (NULL, ?, ?, ?)",
                [testdata, dttestdate, subid]
            );

            // Device factor check
            const devicefactordata = await device_factorcheck(hwid, connection);
            const num_row_factor = devicefactordata.num_row_factor;

            let acetone_factor, acetone_factor_conti, ags_factor_internal, h2_factr, res_factor_up;
            
            if (num_row_factor > 0) {
                acetone_factor = parseFloat(devicefactordata.acetone) || 1;
                acetone_factor_conti = 1; // acetone_continue_reading
                ags_factor_internal = parseFloat(devicefactordata.ags_factor) || 1;
                h2_factr = parseFloat(devicefactordata.h2) || 1;
                res_factor_up = parseFloat(devicefactordata.resp_factor) || 1;
            } else {
                acetone_factor = 1;
                acetone_factor_conti = 1;
                ags_factor_internal = 1;
                h2_factr = 1;
                res_factor_up = 1;
            }

            // Calculate h2 and capacity
            const h2_result = h2600(rawbase2600, rawbest2600, h2_factr, Base_hum, bbtemp);
            const cap = capa(finalpress, duration);

            // Process new sensor data
            const result_new_sensor = await acetone_new_sensor(
                connection,
                raw1820,
                finalraw1820,
                hwid,
                bbtemp,
                finaltemp,
                Base_hum,
                Bm0_hum,
                name,
                rawbase2600,
                rawbest2600,
                acetone_factor,
                h2_factr,
                ags_factor_internal,
                rawbmags,
                finalags,
                rawpress,
                maxpress,
                res_factor_up
            );

            const acepp = result_new_sensor.PPM_MEMS || 0;
            const aceMV = result_new_sensor.mv || 0;
            const ags_factor_1 = 1;
            const dprate = ags_factor_1;
            const ethnol_new_sensor_pmm = result_new_sensor.Ethanol_PPM_data || 0;
            const etholpp = ethnol_new_sensor_pmm;
            const h2_final = result_new_sensor.H2_PPM_data || 0;

            // Insert into g2_new_raw_val_humors
            await connection.execute(
                `INSERT INTO \`g2_new_raw_val_humors\` 
                (\`id\`, \`preval1820\`, \`val1820\`, \`valbest1820\`, \`rawags\`, \`best_ags\`, \`raw_press\`, \`best_press\`, \`max_press\`, \`blow_duration\`, \`date\`, \`hwid\`, \`login\`, \`name\`, \`btemp\`, \`bbtemp\`, \`finaltemp\`, \`main_val1820\`, \`capacity\`, \`tmstamp\`, \`raw2600\`, \`best2600\`, \`Base_hum\`, \`Bm0_hum\`, \`resp_factor\`)
                VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    preval1820, raw1820, finalraw1820, rawbmags, finalags, rawpress, 
                    finalpress, maxpress, duration, date, hwid, login, name, btemp, 
                    bbtemp, finaltemp, rawmain1820, cap, tmstamp, rawbase2600, 
                    rawbest2600, Base_hum, Bm0_hum, res_factor_up
                ]
            );

            const status = 1;
            const responseData = {
                data: [{
                    status: status,
                    AcetonePpm: acepp,
                    ethanolPpm: etholpp,
                    MVacetone: aceMV,
                    H2Ppm: h2_final,
                    hwid: hwid
                }]
            };

            res.json(responseData);
        } catch (dbError) {
            console.error('Database error:', dbError);
            throw dbError;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error processing request:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
};

// Helper functions (kept in the same file as they're tightly coupled with the controller logic)
async function device_factorcheck(hwid, connection) {
    try {
        const [rows] = await connection.execute(
            "SELECT * FROM `respyr_factor` WHERE hwid = ? ORDER BY id DESC LIMIT 1",
            [hwid]
        );
        
        const num_row_factor = rows.length;
        
        if (num_row_factor > 0) {
            const row_factor = rows[0];
            return {
                num_row_factor: num_row_factor,
                acetone: row_factor.acetone,
                ags_factor: row_factor.ags_factor,
                h2: row_factor.h2,
                resp_factor: row_factor.resp_factor
            };
        } else {
            return {
                num_row_factor: 0,
                acetone: 1,
                ags_factor: 1,
                h2: 1,
                resp_factor: 1
            };
        }
    } catch (error) {
        console.error('Error in device_factorcheck:', error);
        return {
            num_row_factor: 0,
            acetone: 1,
            ags_factor: 1,
            h2: 1,
            resp_factor: 1
        };
    }
}

async function acetone_new_sensor(
    connection, raw1820, finalraw1820, hwid, bbtemp, finaltemp,
    basehumid, Bm0_hum, name, raw2600, final2600, acetone_Fact,
    H2_Fact, Ethanol_Fact, rawbmags, finalags, rawpress,
    finalpress, res_factor_up
) {
    try {
        const now = new Date();
        const options = {
            timeZone: 'Asia/Kolkata',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        };
        
        const dateStr = now.toLocaleString('en-US', options);
        const [datePart, timePart] = dateStr.split(', ');
        const [month, day, year] = datePart.split('/');
        const date = `${month}/${day}/${year} ${timePart}`;
        
        const time = Math.floor(Date.now() / 1000);

        const base_temp = parseFloat(bbtemp) || 0;
        const blow_temp = parseFloat(finaltemp) || 0;
        const blow_humid = parseFloat(Bm0_hum) || 0;
        const base_humid = parseFloat(basehumid) || 0;
        const vo = parseFloat(finalraw1820) - parseFloat(raw1820);

        const raw1820_val = parseFloat(raw1820) || 0;
        const finalraw1820_val = parseFloat(finalraw1820) || 0;
        const raw_h2 = parseFloat(raw2600) || 0;
        const final_h2 = parseFloat(final2600) || 0;
        const acetone_Fact_val = parseFloat(acetone_Fact) || 1;
        const H2_Fact_val = parseFloat(H2_Fact) || 1;
        const Ethanol_Fact_val = parseFloat(Ethanol_Fact) || 1;
        const humidity = base_humid;
        const temperature = base_temp;
        const ethnol_ags_diff = parseFloat(finalags) - parseFloat(rawbmags);
        const ags_outcomes = ethnol_ags_diff;
        const finalpress_val = finalpress ? finalpress.toString().substring(0, 20) : '0';
        const rawpress_val = rawpress ? rawpress.toString().substring(0, 20) : '0';
        const fat_factor = 1;

        const result = await fetchMvAndPpm(
            vo, humidity, temperature, raw_h2, final_h2, ags_outcomes,
            acetone_Fact_val, H2_Fact_val, Ethanol_Fact_val, fat_factor,
            hwid, finalags, rawbmags, raw1820_val, finalraw1820_val, connection
        );

        let mv_new_sens = 0, ppm_new_sens = 0, Compensated_Rs_Ro_ratio_data = 0, 
            Ethanol_PPM_data = 0, H2_PPM_data = 0, Ro_data = 0, Rs_data = 0, 
            Rs_Ro_ratio_data = 0, Vout_in_data = 0, Vout_out_data = 0, 
            Acetone_Original_VS_V0 = 0, Adjusted_Acetone_VS_V0 = 0, PPM_MEMS = 0,
            Correction_factor_Acetone_VS_V0 = 0, Correction_factor_ETHANOL_Vs_V0 = 0,
            Correction_factor_H2_RS_R0 = 0, T_Ref_air = 0, RH_Ref_air = 0;

        if (result !== null) {
            mv_new_sens = result.mv || 0;
            ppm_new_sens = result.PPM || 0;
            Compensated_Rs_Ro_ratio_data = result.Compensated_Rs_Ro_ratio || 0;
            Ethanol_PPM_data = result.Ethanol_PPM || 0;
            H2_PPM_data = result.H2_PPM || 0;
            Ro_data = result.Ro || 0;
            Rs_data = result.Rs || 0;
            Rs_Ro_ratio_data = result.Rs_Ro_ratio || 0;
            Vout_in_data = result.Vout_in || 0;
            Vout_out_data = result.Vout_out || 0;
            Acetone_Original_VS_V0 = result.Acetone_Original_VS_V0 || 0;
            Adjusted_Acetone_VS_V0 = result.Adjusted_Acetone_VS_V0 || 0;
            PPM_MEMS = result.PPM_MEMS || 0;
            Correction_factor_Acetone_VS_V0 = result.Correction_factor_Acetone_VS_V0 || 0;
            Correction_factor_ETHANOL_Vs_V0 = result.Correction_factor_ETHANOL_Vs_V0 || 0;
            Correction_factor_H2_RS_R0 = result.Correction_factor_H2_RS_R0 || 0;
            T_Ref_air = result.T_ref_air || 0;
            RH_Ref_air = result.RH_ref_air || 0;
        }

        if (!PPM_MEMS || PPM_MEMS === '' || PPM_MEMS === null) {
            PPM_MEMS = 0;
        }

        let PPM_MEMS_fact_div;
        if (PPM_MEMS !== 0 && PPM_MEMS !== '') {
            PPM_MEMS_fact_div = (PPM_MEMS / acetone_Fact_val).toString().substring(0, 10);
        } else {
            PPM_MEMS_fact_div = PPM_MEMS;
        }

        // Insert into new_test_new_sensors_acetone_data
        await connection.execute(
            `INSERT INTO \`new_test_new_sensors_acetone_data\` 
            (\`id\`, \`login_details\`, \`base_raw_value\`, \`final_raw_value\`, \`base_ags\`, \`final_ags\`, \`h2_raw_base\`, \`h2_raw_final\`, \`vo\`, \`base_temp\`, \`final_temp\`, \`base_humid\`, \`final_humid\`, \`acetone_mv\`, \`Acetone_Original_VS_V0\`, \`Adjusted_Acetone_VS_V0\`, \`acetone_ppm\`, \`Compensated_Rs_Ro_ratio\`, \`Correction_factor_H2_RS_R0\`, \`Correction_factor_ETHANOL_Vs_V0\`, \`Ethanol_PPM\`, \`Correction_factor_Acetone_VS_V0\`, \`H2_PPM\`, \`Ro\`, \`Rs\`, \`Rs_Ro_ratio\`, \`Vout_in\`, \`Vout_out\`, \`base_press\`, \`final_press\`, \`PPM_MEMS\`, \`PPM_MEMS_with_factor\`, \`T_Ref_air\`, \`RH_Ref_air\`, \`ac_hwid_factor\`, \`dttm\`, \`tstammp\`, \`hwid\`)
            VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                name, raw1820_val, finalraw1820_val, rawbmags, finalags, raw_h2, final_h2,
                vo, base_temp, blow_temp, base_humid, blow_humid, mv_new_sens,
                Acetone_Original_VS_V0, Adjusted_Acetone_VS_V0, ppm_new_sens,
                Compensated_Rs_Ro_ratio_data, Correction_factor_H2_RS_R0,
                Correction_factor_ETHANOL_Vs_V0, Ethanol_PPM_data,
                Correction_factor_Acetone_VS_V0, H2_PPM_data, Ro_data, Rs_data,
                Rs_Ro_ratio_data, Vout_in_data, Vout_out_data, rawpress_val,
                finalpress_val, PPM_MEMS, PPM_MEMS_fact_div, T_Ref_air, RH_Ref_air,
                acetone_Fact_val, date, time, hwid
            ]
        );

        return {
            mv: mv_new_sens,
            PPM: ppm_new_sens,
            Compensated_Rs_Ro_ratio_data: Compensated_Rs_Ro_ratio_data,
            Ethanol_PPM_data: Ethanol_PPM_data,
            H2_PPM_data: H2_PPM_data,
            Ro_data: Ro_data,
            Rs_data: Rs_data,
            Rs_Ro_ratio_data: Rs_Ro_ratio_data,
            Vout_in_data: Vout_in_data,
            Vout_out_data: Vout_out_data,
            PPM_MEMS: PPM_MEMS
        };
    } catch (error) {
        console.error('Error in acetone_new_sensor:', error);
        return {
            mv: 0,
            PPM: 0,
            Compensated_Rs_Ro_ratio_data: 0,
            Ethanol_PPM_data: 0,
            H2_PPM_data: 0,
            Ro_data: 0,
            Rs_data: 0,
            Rs_Ro_ratio_data: 0,
            Vout_in_data: 0,
            Vout_out_data: 0,
            PPM_MEMS: 0
        };
    }
}

async function fetchMvAndPpm(vo, humidity, temperature, raw_h2, final_h2, ags_outcomes,
    acetone_Fact, H2_Fact, Ethanol_Fact, fat_factor, hwid, finalags,
    rawbmags, raw1820, finalraw1820, connection) {
    
    try {
        const Vs = finalraw1820;
        const V0 = raw1820;
        
        let T_ref_air = 0;
        let RH_ref_air = 0;
        const time = Math.floor(Date.now() / 1000);
        
        // Get previous data
        const [rows] = await connection.execute(
            "SELECT T_Ref_air, RH_Ref_air, tstammp FROM new_test_new_sensors_acetone_data WHERE hwid = ? ORDER BY id DESC LIMIT 1",
            [hwid]
        );
        
        if (rows.length > 0) {
            const rowbaseht = rows[0];
            if ((time - rowbaseht.tstammp) <= 1800) {
                T_ref_air = parseFloat(rowbaseht.T_Ref_air) || 0;
                RH_ref_air = parseFloat(rowbaseht.RH_Ref_air) || 0;
            } else {
                T_ref_air = parseFloat(temperature) || 0;
                RH_ref_air = parseFloat(humidity) || 0;
            }
        } else {
            T_ref_air = parseFloat(temperature) || 0;
            RH_ref_air = parseFloat(humidity) || 0;
        }
        
        if (!T_ref_air || T_ref_air === '' || T_ref_air === null) {
            T_ref_air = parseFloat(temperature) || 0;
        }
        
        if (!RH_ref_air || RH_ref_air === '' || RH_ref_air === null) {
            RH_ref_air = parseFloat(humidity) || 0;
        }
        
        // Construct URL
        const params = new URLSearchParams({
            input_analog: raw_h2,
            output_analog: final_h2,
            temperature: temperature,
            humidity: humidity,
            vo: vo,
            acetone_Fact: acetone_Fact,
            H2_Fact: H2_Fact,
            Ethanol_Fact: Ethanol_Fact,
            ethanol: ags_outcomes,
            fat_loss_factor: fat_factor,
            VS_ETH: finalags,
            V0_ETH: rawbmags,
            Vs: Vs,
            V0: V0,
            T_ref_air: T_ref_air,
            RH_ref_air: RH_ref_air
        });
        
        const url = `https://respyr.in/predict_mv_h2_data_ht?${params.toString()}`;
        
        const response = await axios.get(url, {
            timeout: 30000 // 30 seconds timeout
        });
        
        let responseData = response.data;
        
        // Replace NaN values
        const responseStr = JSON.stringify(responseData);
        const cleanStr = responseStr.replace(/:NaN/g, ':0');
        const data = JSON.parse(cleanStr);
        
        return {
            mv: data['Acetone mv'] || 0,
            PPM: data['Acetone PPM'] || 0,
            Compensated_Rs_Ro_ratio: data['Compensated_Rs_Ro_ratio'] || 0,
            Acetone_Original_VS_V0: data['Acetone Original VS_minus_V0'] || 0,
            Adjusted_Acetone_VS_V0: data['Adjusted Acetone VS_minus_V0'] || 0,
            Ethanol_PPM: data['Ethanol PPM'] || 0,
            H2_PPM: data['H2 PPM'] || 0,
            Ro: data['Ro'] || 0,
            Rs: data['Rs'] || 0,
            Rs_Ro_ratio: data['Compensated_Rs_Ro_ratio'] || 0,
            Vout_in: data['Vout_in'] || 0,
            Vout_out: data['Vout_out'] || 0,
            PPM_MEMS: data['Acetone PPM_MEMS'] || 0,
            Correction_factor_Acetone_VS_V0: data['Correction_factor_Acetone_VS_V0'] || 0,
            Correction_factor_ETHANOL_Vs_V0: data['Correction_factor_ETHANOL_Vs_V0'] || 0,
            Correction_factor_H2_RS_R0: data['Correction_factor_H2_RS/R0'] || 0,
            T_ref_air: T_ref_air,
            RH_ref_air: RH_ref_air
        };
    } catch (error) {
        console.error('Error fetching data from external API:', error.message);
        return null;
    }
}

function pressure(rawpress, finalpress) {
    return finalpress;
}

async function ethnol(rawbmags, finalags, hwid, ags_factor_1, connection, ags_factor_internal, name) {
    try {
        const now = new Date();
        const options = {
            timeZone: 'Asia/Kolkata',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        };
        
        const dateStr = now.toLocaleString('en-US', options);
        const [datePart, timePart] = dateStr.split(', ');
        const [month, day, year] = datePart.split('/');
        const dttestdate = `${month}/${day}/${year} ${timePart}`;
        
        const ppb_orgi = parseFloat(finalags) - parseFloat(rawbmags);
        const ags_with_fact = (ppb_orgi * parseFloat(ags_factor_1)) || 0;
        const ags_with_fact_internal = ags_with_fact / (parseFloat(ags_factor_internal) || 1);
        
        // Changes on 06/17/2023 2pm
        let ppb = (ags_with_fact_internal / 0.041) / 1000;
        ppb = ppb.toString().substring(0, 10);
        
        return [parseFloat(ppb), ags_with_fact_internal];
    } catch (error) {
        console.error('Error in ethnol function:', error);
        return [0, 0];
    }
}

function capa(finalpress, duration) {
    try {
        const bestval = parseFloat(finalpress) || 0;
        const dur = parseFloat(duration) / 1000;
        const v2 = Math.sqrt(2 * (101325 - bestval) / 1.225);
        const q = (1.77 * Math.pow((v2 / 10), 2)) * 0.001;
        const t = 0.0160 / q;
        const cap = (dur / t) * 0.35 * 0.0160;
        return cap.toString().substring(0, 8);
    } catch (error) {
        console.error('Error in capa function:', error);
        return '0';
    }
}

function h2600(raw2600, final2600, h2_factr, humid, temp) {
    try {
        const Bm0_hum = parseFloat(humid) || 0;
        const bbtemp = parseFloat(temp) || 0;
        const vraw2600 = (parseFloat(raw2600) || 0) * 0.000805664;
        const vfinal2600 = (parseFloat(final2600) || 0) * 0.000805664;
        
        const base_2600_r0 = ((5 / vraw2600) - 1) * 1;
        const final_2600_rs = ((5 / vfinal2600) - 1) * 1;
        const Temp = bbtemp;
        const Humid = Bm0_hum;
        
        const result = 0.3298 + (-0.0007 * Temp) + (-0.0003 * Humid) + 
                       (0.00001772 * (Temp * Humid)) + 
                       (0.00002419 * (Temp * Temp)) + 
                       (0.000003514 * (Humid * Humid));
        
        const sf = result;
        const cal = (final_2600_rs / base_2600_r0) / sf;
        const log2600 = Math.log10(cal);
        
        let PPM;
        if (cal >= 0.32) {
            PPM = Math.pow(10, (-0.57940 - (3.20821 * log2600)));
        } else {
            PPM = Math.pow(10, (-0.23722 - (2.52908 * log2600)));
        }
        
        const PPB = PPM / (parseFloat(h2_factr) || 1);
        return PPB.toString().substring(0, 9);
    } catch (error) {
        console.error('Error in h2600 function:', error);
        return '0';
    }
}