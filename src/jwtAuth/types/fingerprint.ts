export interface FingerPrint {
    userAgent:   string;
    ipAddress:   string;
    country?:    string;
    countryCode?: string;
    region?:     string;
    regionName?: string;
    city?:       string;
    district?:   string;
    lat?:        number;
    lon?:        number;
    timezone?:   string;
    currency?:   string;
    isp?:        string;
    org?:        string;
    as_org?:     string;
    proxy?:      boolean;
    hosting?:    boolean;
    device: string;
    deviceVendor: string;
    deviceModel: string;
    browser: string;
    browserType: string;
    browserVersion: string;
    os: string;
    botAI: boolean;
    bot: boolean;
}
