"""Voice Scam Safety Assistant. It does NOT listen to, record or classify calls. It teaches a verification routine
that works even against a perfect AI voice clone, because it never relies on how the voice sounds."""

STEPS = [
    ("Stay calm and do not send money during the call. Urgency is the scammer's main tool.",
     "शांत रहें और कॉल के दौरान पैसे न भेजें। जल्दबाज़ी ठग का मुख्य हथियार है।"),
    ("End the call. Then call the person back on the number already saved in your phone, never the number that called you.",
     "कॉल काट दें। फिर उस व्यक्ति को आपके फ़ोन में पहले से सेव नंबर पर कॉल करें, कॉल करने वाले नंबर पर नहीं।"),
    ("If they cannot be reached, call another family member or trusted contact to confirm the story.",
     "अगर वे न मिलें तो किसी दूसरे परिवार सदस्य या भरोसेमंद व्यक्ति से पुष्टि करें।"),
    ("Ask for the family safe phrase agreed offline. Treat it as one signal, not absolute proof.",
     "परिवार का ऑफ़लाइन तय किया गया सुरक्षित शब्द पूछें। इसे एक संकेत मानें, पक्का सबूत नहीं।"),
    ("Never share a UPI PIN, OTP or card details, and never approve a collect request, whoever is calling.",
     "कोई भी कॉल करे, UPI पिन, OTP या कार्ड विवरण न बताएं और कलेक्ट रिक्वेस्ट मंज़ूर न करें।"),
    ("Report it: call 1930 (National Cyber Crime helpline) or visit cybercrime.gov.in.",
     "रिपोर्ट करें: 1930 (राष्ट्रीय साइबर अपराध हेल्पलाइन) पर कॉल करें या cybercrime.gov.in पर जाएँ।"),
]
QUESTIONS = [
    ("unknown_number", "The call came from a number not saved in your phone.", "कॉल ऐसे नंबर से आया जो आपके फ़ोन में सेव नहीं है।"),
    ("urgent_money", "They want money immediately.", "वे तुरंत पैसे माँग रहे हैं।"),
    ("secrecy", "They asked you not to tell anyone else.", "उन्होंने किसी और को न बताने को कहा।"),
    ("no_video", "They refuse a video call or to call back on the saved number.", "वे वीडियो कॉल या सेव नंबर पर कॉलबैक से मना करते हैं।"),
    ("new_account", "They gave a new or unfamiliar account / UPI ID to pay.", "उन्होंने भुगतान के लिए नया या अनजान खाता / UPI ID दिया।"),
    ("emotion", "The story is an emergency (accident, arrest, hospital).", "कहानी इमरजेंसी की है (दुर्घटना, गिरफ़्तारी, अस्पताल)।"),
]
CONSENT_EN = "Scam Shield never records or listens to calls or reads your messages. You open this checklist yourself after a suspicious call."
CONSENT_HI = "Scam Shield कभी कॉल रिकॉर्ड नहीं करता, न सुनता है और न आपके संदेश पढ़ता है। संदिग्ध कॉल के बाद आप खुद यह चेकलिस्ट खोलते हैं।"


def guide():
    return {"steps": [{"en": e, "hi": h} for e, h in STEPS],
            "questions": [{"id": i, "en": e, "hi": h} for i, e, h in QUESTIONS],
            "consent_en": CONSENT_EN, "consent_hi": CONSENT_HI}


def evaluate(answers):
    flags = [i for i, _, _ in QUESTIONS if answers.get(i)]
    if len(flags) >= 2:
        return {"level": "High", "flags": flags,
                "en": "Several warning signs match a voice-clone / emergency scam. Do not pay. Follow the steps and call the saved number.",
                "hi": "कई चेतावनी संकेत वॉइस-क्लोन / इमरजेंसी ठगी से मेल खाते हैं। पैसे न भेजें। ऊपर के कदम अपनाएँ और सेव नंबर पर कॉल करें।"}
    if len(flags) == 1:
        return {"level": "Medium", "flags": flags,
                "en": "One warning sign found. Verify through the saved number before doing anything.",
                "hi": "एक चेतावनी संकेत मिला। कुछ भी करने से पहले सेव नंबर से जाँचें।"}
    return {"level": "Low", "flags": [],
            "en": "No listed warning signs ticked. This is not proof the call is genuine; verifying by call-back is still the safest habit.",
            "hi": "कोई चेतावनी संकेत नहीं चुना गया। यह कॉल के असली होने का सबूत नहीं है; कॉलबैक से जाँचना फिर भी सबसे सुरक्षित है।"}
