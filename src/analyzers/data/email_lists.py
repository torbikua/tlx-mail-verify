"""Shared email domain lists for analyzers"""

DISPOSABLE_DOMAINS = frozenset({
    # Major disposable services
    'tempmail.com', 'guerrillamail.com', '10minutemail.com',
    'mailinator.com', 'throwaway.email', 'temp-mail.org',
    'fakeinbox.com', 'maildrop.cc', 'yopmail.com',
    'getnada.com', 'trashmail.com', 'sharklasers.com',
    'guerrillamail.info', 'guerrillamail.de', 'grr.la',
    'dispostable.com', 'mailnesia.com', 'tempail.com',
    'tempinbox.com', 'tempr.email', 'tempmailaddress.com',
    'emailondeck.com', 'mohmal.com', 'mailcatch.com',
    'harakirimail.com', 'guerrillamailblock.com', 'pokemail.net',
    'spam4.me', 'mintemail.com', 'burnermail.io',
    'crazymailing.com', 'discard.email', 'emkei.cz',
    'mailforspam.com', 'nwldx.com', 'rhyta.com',
    'armyspy.com', 'cuvox.de', 'dayrep.com',
    'einrot.com', 'fleckens.hu', 'gustr.com',
    'jourrapide.com', 'superrito.com', 'teleworm.us',
    'mytemp.email', 'tempmailo.com', 'tempmails.net',
    'throwam.com', 'tmpmail.net', 'tmpmail.org',
    'boun.cr', 'bugmenot.com', 'deadaddress.com',
    'despammed.com', 'emailigo.de', 'emailsensei.com',
    'emailtemporario.com.br', 'ephemail.net', 'etranquil.com',
    'garbagemail.org', 'getairmail.com',
    'guerrillamail.net', 'hidemail.de', 'hulapla.de',
    'inboxalias.com', 'jetable.org', 'koszmail.pl',
    'kurzepost.de', 'mailexpire.com',
    'mailhub.pw', 'mailmoat.com', 'mailnull.com',
    'mailscrap.com', 'meltmail.com', 'mobi.web.id',
    'nobulk.com', 'nospamfor.us', 'nowmymail.com',
    'objectmail.com', 'proxymail.eu', 'punkass.com',
    'recode.me', 'safersignup.de', 'spamavert.com',
    'spamfree24.org', 'spamgourmet.com', 'spaml.de',
    'tempemail.co.za', 'tempemail.net', 'trashmail.at',
    'trashmail.io', 'trashmail.me', 'trashmail.net',
    'wegwerfemail.de', 'willselfdestruct.com', 'xoxy.net',
    'mailnator.com', 'maildrop.cc', 'tempsky.com',
    'spambox.us', 'trashymail.com', 'filzmail.com',
    'incognitomail.org', 'mailtemp.info', 'thankyou2010.com',
    'trash-mail.com', 'trash2009.com', 'yolanda.dev',
    'mailsac.com', 'spamhereplease.com', 'emailfake.com',
    'crazymailing.com', 'tempinbox.xyz', 'mailnesia.com',
})

FREE_PROVIDERS = frozenset({
    # International
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'icloud.com', 'aol.com', 'live.com', 'msn.com',
    'protonmail.com', 'proton.me', 'zoho.com', 'zohomail.com',
    'gmx.com', 'gmx.net', 'inbox.com', 'fastmail.com',
    'tutanota.com', 'tuta.io', 'mail.com', 'email.com',
    'pm.me', 'hey.com',
    # Russian
    'mail.ru', 'yandex.ru', 'yandex.com', 'ya.ru',
    'rambler.ru', 'bk.ru', 'list.ru', 'inbox.ru',
    # Ukrainian
    'ukr.net', 'i.ua', 'meta.ua',
    # German
    'web.de', 't-online.de', 'freenet.de',
    # French
    'laposte.net', 'orange.fr', 'sfr.fr',
    # Italian
    'libero.it', 'virgilio.it', 'tin.it',
    # Asian
    'qq.com', '163.com', '126.com', 'sina.com',
    'daum.net', 'naver.com', 'hanmail.net',
})
