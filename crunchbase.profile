https-certificate {
    set CN "1.distilcdn.com";
    set O "DISTIL NETWORKS, INC.";
    set C "US";
    set L "Arlington";
    set OU "Technology";
    set ST "va";
    set validity "365";
}
http-get {
    set uri "/v4/data/autocompletes/";
    client {
        header "Host" "www.crunchbase.com";
        header "Accept" "application/json, text/plain, */*";
        header "Referer" "https://www.crunchbase.com/search/events";
        header "X-Distil-Ajax" "xqrxbybxtayfbaa";
        metadata {
            base64url;
            parameter "query";
        }
        parameter "collection_ids" "locations";
    }
    server {
        header "Cache-Control" "no-cache, private";
        header "Content-Type" "application/json";
        header "Etag" "W/\"1523454251842\"";
        header "Server" "nginx";
        header "Connection" "close";
        output {
            netbios;
            prepend "{\"count\":620,\"entities\":[{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"us-picardie\",\"uuid\":\"7d544b3e-5833-e3db-2bd9-12257a0b3af0\",\"value\":\"Us\"},\"short_description\":\"Us, Picardie, France, Europe\"},{\"facet_ids\":[\"region\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"usak-turkey\",\"uuid\":\"7545bf9e-f369-eb12-36b9-a8d36fd0af18\",\"value\":\"Usak\"},\"short_description\":\"Usak, Turkey, Europe\"},{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"uster-zurich\",\"uuid\":"
            append "\"value\":\"Uster\"},\"short_description\":\"Uster, Zurich, Switzerland, Europe\"},{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"usk-monmouthshire\",\"uuid\":\"37b5f4e4-105b-f0f5-460c-84cd27c4ec07\",\"value\":\"Usk\"},\"short_description\":\"Usk, Monmouthshire, United Kingdom, Europe\"}]}";
        }
    }
}
http-post {
    set uri "/v4/md/searches/events/";
    client {
        header "Host" "www.crunchbase.com";
        header "Accept" "application/json, text/plain, */*";
        header "Referer" "https://www.crunchbase.com/search/events";
        header "X-Distil-Ajax" "xqrxbybxtayfbaa";
        output {
            base64url;
            parameter "query";
        }
        id {
            base64url;
            parameter "collection_ids";
        }
    }
    server {
        header "Cache-Control" "no-cache, private";
        header "Content-Type" "application/json";
        header "Etag" "W/\"1523454251842\"";
        header "Server" "nginx";
        header "Connection" "close";
        output {
            netbios;
            prepend "{\"count\":620,\"entities\":[{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"us-picardie\",\"uuid\":\"7d544b3e-5833-e3db-2bd9-12257a0b3af0\",\"value\":\"Us\"},\"short_description\":\"Us, Picardie, France, Europe\"},{\"facet_ids\":[\"region\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"usak-turkey\",\"uuid\":\"7545bf9e-f369-eb12-36b9-a8d36fd0af18\",\"value\":\"Usak\"},\"short_description\":\"Usak, Turkey, Europe\"},{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"uster-zurich\",\"uuid\":"
            append "\"value\":\"Uster\"},\"short_description\":\"Uster, Zurich, Switzerland, Europe\"},{\"facet_ids\":[\"city\"],\"identifier\":{\"entity_def_id\":\"location\",\"permalink\":\"usk-monmouthshire\",\"uuid\":\"37b5f4e4-105b-f0f5-460c-84cd27c4ec07\",\"value\":\"Usk\"},\"short_description\":\"Usk, Monmouthshire, United Kingdom, Europe\"}]}";
            print;
        }
    }
    http-stager {
        header "Cache-Control" "no-cache, private";
        header "Content-Type" "application/json";
        header "Etag" "W/\"1523454251842\"";
        header "Server" "nginx";
        header "Connection" "close";
    }
}
