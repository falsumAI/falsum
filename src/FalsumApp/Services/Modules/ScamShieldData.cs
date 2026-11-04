using System.Text.RegularExpressions;

namespace FalsumApp.Services.Modules;

// Scam checklist data — extracted verbatim from Falsum-ScamShield.ps1
public static partial class ScamShieldData
{
    public sealed class Step { public string Id=""; public string Q=""; public string Good=""; public int W; public string How=""; }

    public static readonly Dictionary<string, Step[]> Checklists = new()
    {
        ["romance"] = new Step[]
        {
            new() { Id="R1", Q="Have you video-called them live (not a recorded clip)?", Good="y", W=30, How="Demand a live call with an unpredictable gesture (hold up 3 fingers, say today's date). Refusal = fail." },
            new() { Id="R2", Q="Did you reverse-image-search their photos?", Good="y", W=20, How="Save the photo, search it on TinEye / Google Images. Same photo under other names = fail." },
            new() { Id="R3", Q="Have they asked for money, gift cards, or crypto for ANY reason?", Good="n", W=40, How="Emergency, plane ticket, customs fee — the story changes, the ask doesn't. Any ask = fail." },
            new() { Id="R4", Q="Can you verify them through an independent channel?", Good="y", W=20, How="Find them outside the dating app: employer, public records, people-track username search. Ghost = fail." },
            new() { Id="R5", Q="Are they avoiding meeting in person with endless excuses?", Good="n", W=15, How="Deployed soldier, oil rig, doctor abroad — classic scripts. Pattern match = fail." },
        },
        ["grandparent"] = new Step[]
        {
            new() { Id="G1", Q="Did you verify the caller's identity through a KNOWN number?", Good="y", W=40, How="Hang up. Call your grandchild on the number YOU have saved — not the one the caller gives you." },
            new() { Id="G2", Q="Did the caller demand secrecy ('don't tell mom and dad')?", Good="n", W=25, How="Secrecy is the mechanism. Real emergencies don't need secrecy." },
            new() { Id="G3", Q="Is payment demanded via gift cards, wire, or cash pickup?", Good="n", W=35, How="No bail bondsman, lawyer, or hospital takes iTunes cards. Any such demand = fail." },
            new() { Id="G4", Q="Did you ask a question only the real person could answer?", Good="y", W=20, How="A shared memory, a pet's name. Voice cloning beats hello; it doesn't beat specifics." },
        },
        ["investment"] = new Step[]
        {
            new() { Id="I1", Q="Is the platform registered? (SEC/FINRA check)", Good="y", W=30, How="Search the firm on SEC EDGAR / FINRA BrokerCheck. Unregistered + promises returns = fail." },
            new() { Id="I2", Q="Are returns guaranteed or unusually high?", Good="n", W=25, How="'Guaranteed 20% monthly' is mathematically a Ponzi. Guaranteed = fail." },
            new() { Id="I3", Q="Can you withdraw easily, or only deposit?", Good="y", W=30, How="Try a small withdrawal early. Deposit-only, fees-to-withdraw, 'taxes due first' = fail." },
            new() { Id="I4", Q="Did contact come unsolicited (DM, wrong-number text)?", Good="n", W=15, How="Pig-butchering starts with 'sorry, wrong number'. Unsolicited = fail." },
            new() { Id="I5", Q="Is pressure applied to act now / keep it secret?", Good="n", W=20, How="Urgency + secrecy = the two levers. Both present = fail." },
        },
        ["job"] = new Step[]
        {
            new() { Id="J1", Q="Did they ask YOU for money (equipment, training, background check)?", Good="n", W=35, How="Real employers pay you. Any upfront fee = fail." },
            new() { Id="J2", Q="Is the company verifiable independently?", Good="y", W=25, How="Company website (check domain age), LinkedIn employees, physical address. Ghost company = fail." },
            new() { Id="J3", Q="Did a real interview happen (not text-only)?", Good="y", W=20, How="Text-only 'interview' over chat apps = fail." },
            new() { Id="J4", Q="Were you sent a check to deposit and forward funds?", Good="n", W=40, How="Fake-check/mule scheme. Any check + forward instruction = fail and report." },
        },
        ["rental"] = new Step[]
        {
            new() { Id="N1", Q="Have you seen the property interior in person or via live video?", Good="y", W=30, How="Photos-only listings get scraped from real sales. No interior access = fail." },
            new() { Id="N2", Q="Is the price far below market for the area?", Good="n", W=20, How="Bait pricing. Check 3 comparable listings." },
            new() { Id="N3", Q="Does the 'landlord' refuse in-person meeting / demand wire before keys?", Good="n", W=35, How="Money before keys, sight unseen = fail." },
            new() { Id="N4", Q="Does the lister claim to be abroad / missionary / military?", Good="n", W=15, How="Classic script. Verify ownership via county assessor records." },
        },
        ["techsupport"] = new Step[]
        {
            new() { Id="T1", Q="Did THEY contact YOU (call, popup, email) claiming a problem?", Good="n", W=35, How="Microsoft/Apple/Google never call about your computer. Unsolicited = fail." },
            new() { Id="T2", Q="Did they ask for remote access (AnyDesk, TeamViewer)?", Good="n", W=35, How="Remote access = the heist. Never grant to unsolicited callers." },
            new() { Id="T3", Q="Is payment demanded via gift cards or wire?", Good="n", W=30, How="No legit support takes gift cards. Ever." },
            new() { Id="T4", Q="Did a browser popup with a phone number claim virus infection?", Good="n", W=20, How="Popups are ads, not diagnoses. Close the browser; the 'virus' vanishes." },
        },
        ["smishing"] = new Step[]
        {
            new() { Id="S1", Q="Did the text come from a random 10-digit number or email-to-text?", Good="n", W=20, How="Banks/shippers don't text from random mobiles. Check the sender." },
            new() { Id="S2", Q="Does it demand urgency + a link (package held, account locked)?", Good="n", W=25, How="Go to the company's site/app directly — never the link. Compare." },
            new() { Id="S3", Q="Does the link domain match the real company?", Good="y", W=30, How="Read the domain character by character. usps-track-package.top is not usps.com." },
            new() { Id="S4", Q="Were you expecting this message?", Good="y", W=15, How="Unexpected + link + urgency = the whole playbook." },
        },
        ["vishing"] = new Step[]
        {
            new() { Id="V1", Q="Did you verify via a number YOU looked up independently?", Good="y", W=40, How="Hang up. Call the number on your card / statement / official site." },
            new() { Id="V2", Q="Are they asking for full SSN, passwords, or codes texted to you?", Good="n", W=35, How="No legit caller asks for the code they just sent you. That code is the keys." },
            new() { Id="V3", Q="Is there urgency + secrecy?", Good="n", W=20, How="Same levers as every other scam. Recognize the shape." },
        },
        ["deepfake"] = new Step[]
        {
            new() { Id="D1", Q="Can you verify through a second channel?", Good="y", W=40, How="Video call from 'the boss'? Message them on another app, call their known number. One channel is never enough now." },
            new() { Id="D2", Q="Does the request break normal procedure?", Good="n", W=25, How="Urgent wire, skip approvals, keep it quiet — procedure exists to stop exactly this." },
            new() { Id="D3", Q="Do you have a family/office code word?", Good="y", W=20, How="Set one TODAY with family and coworkers: 'what's the code word?' defeats cloned voices." },
            new() { Id="D4", Q="Are you being asked to confirm identity with video/audio?", Good="n", W=15, How="Your face/voice are now keys. Don't hand biometric samples to unverified callers." },
        },
    };

    public sealed class PayTerm { public string Term=""; public int W; public string Why=""; }
    public static readonly PayTerm[] PaymentTerms = new PayTerm[]
    {
        new() { Term="steam card", W=35, Why="Steam/gift cards are irreversible and untraceable — the #1 scam payout." },
        new() { Term="itunes card", W=35, Why="iTunes/App Store cards are irreversible — no legit business takes them." },
        new() { Term="google play card", W=35, Why="Play cards are irreversible — no legit business takes them." },
        new() { Term="gift card", W=30, Why="Gift cards are irreversible — no legit bill, bail, or support takes them." },
        new() { Term="giftcard", W=30, Why="Gift cards are irreversible — no legit bill, bail, or support takes them." },
        new() { Term="western union", W=30, Why="WU transfers are cash-like: gone in minutes, hard to recall." },
        new() { Term="moneygram", W=30, Why="MoneyGram transfers are cash-like: gone in minutes, hard to recall." },
        new() { Term="wire transfer", W=25, Why="Wire transfers are hard to reverse — recall windows are hours." },
        new() { Term="bank wire", W=25, Why="Wire transfers are hard to reverse — recall windows are hours." },
        new() { Term="crypto", W=25, Why="Crypto is irreversible. 'Send crypto' = the money is gone." },
        new() { Term="bitcoin", W=25, Why="Bitcoin is irreversible. 'Send bitcoin' = the money is gone." },
        new() { Term="usdt", W=25, Why="USDT is irreversible — the stablecoin of pig-butchering payouts." },
        new() { Term="ethereum", W=25, Why="ETH is irreversible. 'Send ETH' = the money is gone." },
        new() { Term="prepaid card", W=25, Why="Prepaid/reloadable cards are cash-like and untraceable." },
        new() { Term="zelle", W=20, Why="Zelle is instant and bank-to-bank — reversals are rare." },
        new() { Term="cashapp", W=20, Why="Cash App is instant P2P — reversals are rare." },
        new() { Term="cash app", W=20, Why="Cash App is instant P2P — reversals are rare." },
        new() { Term="venmo", W=20, Why="Venmo is instant P2P — reversals are rare." },
        new() { Term="cashier's check", W=20, Why="Fake cashier's checks + 'forward the rest' = the classic mule trap." },
        new() { Term="money order", W=15, Why="Money orders are cash-like; combined with urgency they are a flag." },
    };
}
