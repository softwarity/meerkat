package auth

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Flow-page localization (I18N): the language and the color scheme are USER
// preferences, persisted in cookies and applied server-side on every page of
// the flow — no flash, no JS framework. The language falls back to
// Accept-Language, the scheme to the system (CSS light-dark()).
const (
	langCookie   = "MEERKAT_LANG"   // "en" | "fr"
	schemeCookie = "MEERKAT_SCHEME" // "auto" | "light" | "dark"
)

// prefs is the resolved pair for one request.
type prefs struct {
	Lang   string // catalogue key
	Scheme string // "auto" | "light" | "dark"
}

// prefsOf resolves the request's preferences WITHIN the languages the
// integrator offers (I18N: the entry pages must match the target
// application's languages — configured in Application → General).
func prefsOf(r *http.Request, offered []string) prefs {
	p := prefs{Lang: "", Scheme: "auto"}
	if c, err := r.Cookie(langCookie); err == nil && contains(offered, c.Value) {
		p.Lang = c.Value
	}
	if p.Lang == "" {
		p.Lang = matchAcceptLanguage(r.Header.Get("Accept-Language"), offered)
	}
	if c, err := r.Cookie(schemeCookie); err == nil {
		switch c.Value {
		case "light", "dark":
			p.Scheme = c.Value
		}
	}
	return p
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// matchAcceptLanguage picks the first OFFERED language of the header — enough
// for a small catalogue, no full RFC 4647 machinery. Nothing matches → the
// integrator's first language.
func matchAcceptLanguage(header string, offered []string) string {
	for _, part := range strings.Split(header, ",") {
		lang := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if len(lang) >= 2 && contains(offered, lang[:2]) {
			return lang[:2]
		}
	}
	if len(offered) > 0 {
		return offered[0]
	}
	return "en"
}

// offeredLanguages is what the FLOW PAGES speak: the RIGHT JOIN of the
// application's locale pool (SettingLanguages) with the languages Meerkat
// actually embeds (the messages catalogue). An app locale Meerkat does not
// embed (e.g. vi) never reaches the flow pages; an empty pool falls back to
// English. Cached alongside the theme (same 5s staleness budget).
func (h *Handler) offeredLanguages() []string {
	h.themeMu.Lock()
	defer h.themeMu.Unlock()
	if time.Since(h.langsReadAt) < 5*time.Second && len(h.langsCache) > 0 {
		return h.langsCache
	}
	var appLangs []string
	_ = h.st.GetSetting(context.Background(), store.SettingLanguages, &appLangs)
	out := make([]string, 0, len(appLangs))
	for _, l := range appLangs {
		if _, ok := messages[l]; ok {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = []string{"en"}
	}
	h.langsCache = out
	h.langsReadAt = time.Now()
	return out
}

// flowChrome is the shared model every flow page embeds: theme, branding and
// the request's language/scheme preferences.
type flowChrome struct {
	ThemeCSS template.CSS
	Brand    brandView
	Title    string
	Lang     string   // <html lang>
	Langs    []string // the offered languages (switcher hidden when 1)
	// Scheme drives the CSS (:root color-scheme); SchemeSwitch shows the
	// buttons. The ADMIN plane is Meerkat's console: dark only, no choice —
	// the theme/scheme options only ever concern the DATA plane's pages.
	Scheme       string
	SchemeSwitch bool
	// LangNames maps codes to endonyms for the language menu; SchemeIcon /
	// SchemeNext drive the single 3-state scheme button (auto→light→dark).
	LangNames  map[string]string
	SchemeIcon string
	SchemeNext string
	T          map[string]string // the locale's message catalogue
}

// flowData assembles the chrome for one request: theme + branding + prefs.
func (h *Handler) flowData(r *http.Request, titleKey string) flowChrome {
	css, brand := h.chrome()
	offered := h.offeredLanguages()
	p := prefsOf(r, offered)
	t := messages[p.Lang]
	chrome := flowChrome{
		ThemeCSS:     css,
		Brand:        brand,
		Title:        t[titleKey],
		Lang:         p.Lang,
		Langs:        offered,
		Scheme:       p.Scheme,
		SchemeSwitch: true,
	}
	chrome.T = t
	if h.adminPlane {
		chrome.Scheme = "dark"
		chrome.SchemeSwitch = false
	}
	chrome.LangNames = langNames
	chrome.SchemeIcon = map[string]string{"auto": "◐", "light": "☀", "dark": "☾"}[chrome.Scheme]
	chrome.SchemeNext = map[string]string{"auto": "light", "light": "dark", "dark": "auto"}[chrome.Scheme]
	return chrome
}

// tr translates one key for the request's language.
func (h *Handler) tr(r *http.Request, key string) string {
	return messages[prefsOf(r, h.offeredLanguages()).Lang][key]
}

// langNames are the endonyms shown by language pickers (never translated).
var langNames = map[string]string{
	"en": "English",
	"fr": "Français",
}

// messages is the flow pages' catalogue. Two locales, kept complete in both —
// a missing key would render empty, so the tests compare the maps' key sets.
// ADDING A LANGUAGE: add its map here, its endonym to langNames, and its code
// to store.SupportedLanguages — nothing else.
var messages = map[string]map[string]string{
	"en": {
		// titles
		"titleSignIn":         "Sign in · Meerkat",
		"titleChooseTenant":   "Choose your tenant · Meerkat",
		"titleUpdatePassword": "Update your password · Meerkat",
		"titleProfile":        "Profile · Meerkat",
		"titleChangePassword": "Change your password · Meerkat",
		"titleTwoFactor":      "Two-factor · Meerkat",
		"titleSetupTwoFactor": "Set up two-factor · Meerkat",

		// login
		"username":           "Username",
		"password":           "Password",
		"signIn":             "Sign in",
		"signOut":            "Sign out",
		"continueWithout":    "Or continue without signing in",
		"errInvalidCreds":    "Invalid username or password.",
		"errOutsideHours":    "Access refused: outside your working hours.",
		"errTenantRefused":   "Access to %s is refused: outside your working hours.",
		"errTenantForbidden": "That tenant is not available to your account.",

		// passwords
		"mustChangeLead":     "Your password must be changed",
		"changePasswordLead": "Change your password",
		"currentPassword":    "Current password",
		"newPassword":        "New password",
		"confirmPassword":    "Confirm password",
		"changePassword":     "Change password",
		"errPwTooShort":      "The new password needs at least 8 characters.",
		"errPwMismatch":      "The two entries do not match.",
		"errPwCurrentWrong":  "Your current password is incorrect.",

		// tenant selection
		"chooseTenantLead": "Choose the tenant to work in",

		// group selection (exclusive mode, RBAC-03)
		"titleChooseGroup":  "Choose your group · Meerkat",
		"chooseGroupLead":   "Choose the group to work as",
		"errGroupForbidden": "That group is not yours to choose.",
		"group":             "Group",

		// profile
		"factUser":              "User",
		"factName":              "Name",
		"factEmail":             "Email",
		"factOrganisation":      "Organisation",
		"twoFactor":             "Two-factor authentication",
		"mfaOn":                 "On",
		"mfaOff":                "Off",
		"mfaRequired":           "Required",
		"cancel":                "Cancel",
		"backToProfile":         "Back to profile",
		"security":              "Security",
		"developer":             "Developer",
		"back":                  "Back",
		"titleSecurity":         "Security · Meerkat",
		"titleDeveloper":        "Developer · Meerkat",
		"thisBrowser":           "This browser",
		"passkeys":              "Passkeys",
		"addPasskey":            "Add a passkey",
		"passkeyRemove":         "Remove",
		"signInPasskey":         "Sign in with a passkey",
		"errPasskey":            "The passkey sign-in failed. Try again, or use your password.",
		"devCert":               "Developer certificate",
		"devCertHint":           "Paste your PUBLIC certificate (PEM): your plugged services will authenticate with it.",
		"devCertSave":           "Save certificate",
		"devCertRemove":         "Remove certificate",
		"devCertSubject":        "Subject",
		"devCertFingerprint":    "Fingerprint",
		"devCertExpires":        "Expires",
		"errBadCert":            "This is not a valid PEM certificate.",
		"signinHistory":         "Sign-in history",
		"titleRegister":         "Create your account · Meerkat",
		"titleConfirmed":        "Account confirmed · Meerkat",
		"titlePending":          "Awaiting access · Meerkat",
		"email":                 "Email",
		"fullname":              "Full name",
		"registerLead":          "Create your account",
		"registerCta":           "Create my account",
		"createAccount":         "Create an account",
		"backToLogin":           "Back to sign in",
		"registerSentLead":      "Check your inbox",
		"registerSentHint":      "If this address is valid, a confirmation link has been sent to it. The link expires in 24 hours.",
		"confirmedLead":         "Your account is confirmed",
		"confirmedHint":         "An administrator still has to grant you access; you will be able to sign in meanwhile.",
		"pendingLead":           "Your account is awaiting access",
		"pendingHint":           "An administrator has been notified and must grant you access. Come back later, or use the public areas below.",
		"errRegisterMissing":    "Username and email are required.",
		"errBadEmail":           "This is not a valid email address.",
		"errTooManyAttempts":    "Too many attempts: try again later.",
		"errConfirmExpired":     "This confirmation link is invalid or expired: sign in to receive a fresh one.",
		"titleTokens":           "API tokens · Meerkat",
		"apiTokens":             "API tokens",
		"copy":                  "Copy",
		"tokenContext":          "New tokens act in this context:",
		"tokenContextNone":      "no active tenant",
		"tokenNoTenant":         "Without an active tenant a token carries your identity but no roles.",
		"tokenNamePlaceholder":  "e.g. CI pipeline",
		"tokenNameLabel":        "Name",
		"tokenValidity":         "Validity",
		"tokenListTitle":        "Your tokens",
		"done":                  "Done",
		"tokenCreate":           "Create a token",
		"tokenCreatedLead":      "Copy your token now",
		"tokenCreatedWarn":      "This is the only time it is shown. Store it somewhere safe; anyone with it can call the API as you.",
		"tokenDisabled":         "disabled",
		"tokenDisable":          "Disable",
		"tokenEnable":           "Enable",
		"tokenRevoke":           "Revoke",
		"tokenRevokeConfirm":    "Anything using this token will stop working immediately. This cannot be undone.",
		"errTokenName":          "Give the token a name.",
		"days30":                "30 days",
		"days60":                "60 days",
		"days90":                "90 days",
		"year1":                 "1 year",
		"never":                 "No expiration",
		"expired":               "expired",
		"until":                 "until",
		"lastUsed":              "last used",
		"titleForgot":           "Forgot password · Meerkat",
		"titleReset":            "New password · Meerkat",
		"forgotLink":            "Forgot your password?",
		"forgotLead":            "Forgot your password?",
		"forgotHint":            "Enter your account's email address: a reset link will be sent to it (valid 1 hour).",
		"forgotCta":             "Send me a reset link",
		"forgotSentHint":        "If this address matches an account, a reset link has been sent to it. The link expires in 1 hour.",
		"resetLead":             "Choose a new password",
		"resetCta":              "Set my new password",
		"errResetExpired":       "This reset link is invalid or expired: ask for a fresh one from the sign-in page.",
		"resetDoneLead":         "Your password is updated",
		"resetDoneHint":         "Every open session has been signed out; sign in with your new password.",
		"mailResetSubject":      "Reset your %s password",
		"mailResetBody":         "A password reset was requested for your %s account.\n\nOpen this link to choose a new password (valid 1 hour):\n%s\n\nIf you did not ask for it, ignore this message: your password is unchanged.",
		"mailResetHTML":         "A password reset was requested for your %s account. Click the link below to choose a new password (valid 1 hour). If you did not ask for it, ignore this message: your password is unchanged.",
		"mailResetCta":          "Choose a new password",
		"mailPwChangedSubject":  "Your %s password was changed",
		"mailPwChangedBody":     "The password of your %s account was just changed and every open session was signed out.\n\nIf this was not you, use the sign-in page's password reset immediately and warn your administrator.",
		"captchaLabel":          "Anti-robot check: copy the digits",
		"captchaAlt":            "Distorted digits to copy",
		"captchaNew":            "New image",
		"errCaptcha":            "The digits do not match the image: try this new one.",
		"mailConfirmSubject":    "Confirm your %s account",
		"mailConfirmBody":       "Welcome to %s.\n\nConfirm your address by opening this link (valid 24 hours):\n%s\n\nIf you did not create this account, ignore this message.",
		"mailConfirmHTML":       "Welcome to %s. Confirm your address by clicking the link below (valid 24 hours). If you did not create this account, ignore this message.",
		"mailConfirmCta":        "Confirm my address",
		"mailNewAccountSubject": "%s: a new account awaits access",
		"mailNewAccountBody":    "The account %q (%s) confirmed its address on %s and awaits access.\n\nGrant it roles or a tenant in the console, Users section.",
		"titleHistory":          "Sign-in history · Meerkat",
		"historyEmpty":          "No sign-in recorded yet.",
		"methodPassword":        "password",
		"methodTotp":            "password + code",
		"methodPasskey":         "passkey",

		// totp challenge
		"challengeHint": "Enter the 6-digit code from your authenticator app, or one of your backup codes.",
		"authCode":      "Authentication code",
		"trustDays":     "Trust this browser for %d days",
		"verify":        "Verify",
		"errBadCode":    "That code is not valid.",

		// totp enrolment
		"saveBackupCodes": "Save your backup codes",
		"backupHint":      "Each code works once if you lose your authenticator. Store them somewhere safe: they won't be shown again.",
		"savedContinue":   "I've saved them, continue",
		"mfaRequiredLead": "Two-factor is required",
		"setupLead":       "Set up two-factor",
		"scanHint":        "Scan this with an authenticator app, or enter the key by hand, then type the 6-digit code to confirm.",
		"qrAlt":           "Enrolment QR code",
		"setupKey":        "Setup key",
		"sixDigitCode":    "6-digit code",
		"confirm":         "Confirm",
		"errBadCodeRetry": "That code is not valid. Try again.",

		// mfa management
		"mfaStatus":         "Two-factor is active. Backup codes remaining: %d of %d.",
		"replaceAuth":       "Replace authenticator",
		"regenCodes":        "Regenerate backup codes",
		"turnOffMfa":        "Turn off two-factor",
		"mfaRequiredNote":   "Two-factor is required by your organization and can't be turned off.",
		"errMfaRequiredOff": "Two-factor is required and cannot be turned off.",
		"trustedBrowsers":   "Trusted browsers",
		"untilDate":         "until %s",
		"revoke":            "Revoke",
		"revokeAll":         "Revoke all trusted browsers",

		// preference switchers
		"schemeAuto":  "Follow the system",
		"schemeLight": "Light",
		"schemeDark":  "Dark",

		// user button menu
		"profile":      "Profile",
		"languages":    "Languages",
		"colorScheme":  "Color scheme",
		"tenant":       "Tenant",
		"applications": "Applications",

		// profile photo
		"changePhoto":   "Change photo",
		"removePhoto":   "Remove photo",
		"errAvatarType": "Use a png, jpeg or webp image",
		"errAvatarSize": "Keep the photo under 200 KiB",
	},
	"fr": {
		// titles
		"titleSignIn":         "Connexion · Meerkat",
		"titleChooseTenant":   "Choisissez votre tenant · Meerkat",
		"titleUpdatePassword": "Changez votre mot de passe · Meerkat",
		"titleProfile":        "Profil · Meerkat",
		"titleChangePassword": "Changer votre mot de passe · Meerkat",
		"titleTwoFactor":      "Double authentification · Meerkat",
		"titleSetupTwoFactor": "Activer la double authentification · Meerkat",

		// login
		"username":           "Identifiant",
		"password":           "Mot de passe",
		"signIn":             "Se connecter",
		"signOut":            "Se déconnecter",
		"continueWithout":    "Ou continuer sans se connecter",
		"errInvalidCreds":    "Identifiant ou mot de passe invalide.",
		"errOutsideHours":    "Accès refusé : en dehors de vos heures ouvrées.",
		"errTenantRefused":   "L'accès à %s est refusé : en dehors de vos heures ouvrées.",
		"errTenantForbidden": "Ce tenant n'est pas disponible pour votre compte.",

		// passwords
		"mustChangeLead":     "Votre mot de passe doit être changé",
		"changePasswordLead": "Changer votre mot de passe",
		"currentPassword":    "Mot de passe actuel",
		"newPassword":        "Nouveau mot de passe",
		"confirmPassword":    "Confirmez le mot de passe",
		"changePassword":     "Changer le mot de passe",
		"errPwTooShort":      "Le nouveau mot de passe doit faire au moins 8 caractères.",
		"errPwMismatch":      "Les deux saisies ne correspondent pas.",
		"errPwCurrentWrong":  "Votre mot de passe actuel est incorrect.",

		// tenant selection
		"chooseTenantLead": "Choisissez le tenant de travail",

		// group selection (exclusive mode, RBAC-03)
		"titleChooseGroup":  "Choisissez votre groupe · Meerkat",
		"chooseGroupLead":   "Choisissez le groupe avec lequel travailler",
		"errGroupForbidden": "Ce groupe ne vous appartient pas.",
		"group":             "Groupe",

		// profile
		"factUser":              "Utilisateur",
		"factName":              "Nom",
		"factEmail":             "E-mail",
		"factOrganisation":      "Organisation",
		"twoFactor":             "Double authentification",
		"mfaOn":                 "Activée",
		"mfaOff":                "Inactive",
		"mfaRequired":           "Requise",
		"cancel":                "Annuler",
		"backToProfile":         "Retour au profil",
		"security":              "Sécurité",
		"developer":             "Développeur",
		"back":                  "Retour",
		"titleSecurity":         "Sécurité · Meerkat",
		"titleDeveloper":        "Développeur · Meerkat",
		"thisBrowser":           "Ce navigateur",
		"passkeys":              "Passkeys",
		"addPasskey":            "Ajouter une passkey",
		"passkeyRemove":         "Retirer",
		"signInPasskey":         "Se connecter avec une passkey",
		"errPasskey":            "La connexion par passkey a échoué. Réessayez, ou utilisez votre mot de passe.",
		"devCert":               "Certificat développeur",
		"devCertHint":           "Collez votre certificat PUBLIC (PEM) : vos services branchés s'authentifieront avec.",
		"devCertSave":           "Enregistrer le certificat",
		"devCertRemove":         "Retirer le certificat",
		"devCertSubject":        "Sujet",
		"devCertFingerprint":    "Empreinte",
		"devCertExpires":        "Expire",
		"errBadCert":            "Ce n'est pas un certificat PEM valide.",
		"signinHistory":         "Historique de connexions",
		"titleRegister":         "Créez votre compte · Meerkat",
		"titleConfirmed":        "Compte confirmé · Meerkat",
		"titlePending":          "En attente d'accès · Meerkat",
		"email":                 "E-mail",
		"fullname":              "Nom complet",
		"registerLead":          "Créez votre compte",
		"registerCta":           "Créer mon compte",
		"createAccount":         "Créer un compte",
		"backToLogin":           "Retour à la connexion",
		"registerSentLead":      "Vérifiez votre boîte mail",
		"registerSentHint":      "Si cette adresse est valide, un lien de confirmation vient d'y être envoyé. Le lien expire dans 24 heures.",
		"confirmedLead":         "Votre compte est confirmé",
		"confirmedHint":         "Un administrateur doit encore vous accorder des accès ; vous pouvez déjà vous connecter en attendant.",
		"pendingLead":           "Votre compte est en attente d'accès",
		"pendingHint":           "Un administrateur a été prévenu et doit vous accorder des accès. Revenez plus tard, ou utilisez les espaces publics ci-dessous.",
		"errRegisterMissing":    "L'identifiant et l'e-mail sont requis.",
		"errBadEmail":           "Cette adresse e-mail n'est pas valide.",
		"errTooManyAttempts":    "Trop de tentatives : réessayez plus tard.",
		"errConfirmExpired":     "Ce lien de confirmation est invalide ou expiré : connectez-vous pour en recevoir un nouveau.",
		"titleTokens":           "Jetons API · Meerkat",
		"apiTokens":             "Jetons API",
		"copy":                  "Copier",
		"tokenContext":          "Les nouveaux jetons agissent dans ce contexte :",
		"tokenContextNone":      "aucun tenant actif",
		"tokenNoTenant":         "Sans tenant actif, un jeton porte votre identité mais aucun rôle.",
		"tokenNamePlaceholder":  "ex. pipeline CI",
		"tokenNameLabel":        "Nom",
		"tokenValidity":         "Validité",
		"tokenListTitle":        "Vos jetons",
		"done":                  "Terminé",
		"tokenCreate":           "Créer un jeton",
		"tokenCreatedLead":      "Copiez votre jeton maintenant",
		"tokenCreatedWarn":      "C'est la seule fois où il s'affiche. Conservez-le en lieu sûr ; quiconque le détient peut appeler l'API en votre nom.",
		"tokenDisabled":         "désactivé",
		"tokenDisable":          "Désactiver",
		"tokenEnable":           "Activer",
		"tokenRevoke":           "Révoquer",
		"tokenRevokeConfirm":    "Tout ce qui utilise ce jeton cessera de fonctionner immédiatement. C'est irréversible.",
		"errTokenName":          "Donnez un nom au jeton.",
		"days30":                "30 jours",
		"days60":                "60 jours",
		"days90":                "90 jours",
		"year1":                 "1 an",
		"never":                 "Sans expiration",
		"expired":               "expiré",
		"until":                 "jusqu'au",
		"lastUsed":              "dernière utilisation",
		"titleForgot":           "Mot de passe oublié · Meerkat",
		"titleReset":            "Nouveau mot de passe · Meerkat",
		"forgotLink":            "Mot de passe oublié ?",
		"forgotLead":            "Mot de passe oublié ?",
		"forgotHint":            "Saisissez l'adresse e-mail de votre compte : un lien de réinitialisation y sera envoyé (valable 1 heure).",
		"forgotCta":             "M'envoyer un lien de réinitialisation",
		"forgotSentHint":        "Si cette adresse correspond à un compte, un lien de réinitialisation vient d'y être envoyé. Le lien expire dans 1 heure.",
		"resetLead":             "Choisissez un nouveau mot de passe",
		"resetCta":              "Définir mon nouveau mot de passe",
		"errResetExpired":       "Ce lien de réinitialisation est invalide ou expiré : redemandez-en un depuis la page de connexion.",
		"resetDoneLead":         "Votre mot de passe est mis à jour",
		"resetDoneHint":         "Toutes les sessions ouvertes ont été déconnectées ; connectez-vous avec votre nouveau mot de passe.",
		"mailResetSubject":      "Réinitialisez votre mot de passe %s",
		"mailResetBody":         "Une réinitialisation de mot de passe a été demandée pour votre compte %s.\n\nOuvrez ce lien pour choisir un nouveau mot de passe (valable 1 heure) :\n%s\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez ce message : votre mot de passe est inchangé.",
		"mailResetHTML":         "Une réinitialisation de mot de passe a été demandée pour votre compte %s. Cliquez le lien ci-dessous pour choisir un nouveau mot de passe (valable 1 heure). Si vous n'êtes pas à l'origine de cette demande, ignorez ce message : votre mot de passe est inchangé.",
		"mailResetCta":          "Choisir un nouveau mot de passe",
		"mailPwChangedSubject":  "Votre mot de passe %s a été changé",
		"mailPwChangedBody":     "Le mot de passe de votre compte %s vient d'être changé et toutes les sessions ouvertes ont été déconnectées.\n\nSi ce n'était pas vous, utilisez immédiatement la réinitialisation de mot de passe de la page de connexion et prévenez votre administrateur.",
		"captchaLabel":          "Vérification anti-robot : recopiez les chiffres",
		"captchaAlt":            "Chiffres déformés à recopier",
		"captchaNew":            "Nouvelle image",
		"errCaptcha":            "Les chiffres ne correspondent pas à l'image : essayez avec celle-ci.",
		"mailConfirmSubject":    "Confirmez votre compte %s",
		"mailConfirmBody":       "Bienvenue sur %s.\n\nConfirmez votre adresse en ouvrant ce lien (valable 24 heures) :\n%s\n\nSi vous n'avez pas créé ce compte, ignorez ce message.",
		"mailConfirmHTML":       "Bienvenue sur %s. Confirmez votre adresse en cliquant le lien ci-dessous (valable 24 heures). Si vous n'avez pas créé ce compte, ignorez ce message.",
		"mailConfirmCta":        "Confirmer mon adresse",
		"mailNewAccountSubject": "%s : un nouveau compte attend ses accès",
		"mailNewAccountBody":    "Le compte %q (%s) a confirmé son adresse sur %s et attend ses accès.\n\nAccordez-lui des rôles ou un tenant dans la console, section Users.",
		"titleHistory":          "Historique de connexions · Meerkat",
		"historyEmpty":          "Aucune connexion enregistrée pour l'instant.",
		"methodPassword":        "mot de passe",
		"methodTotp":            "mot de passe + code",
		"methodPasskey":         "passkey",

		// totp challenge
		"challengeHint": "Saisissez le code à 6 chiffres de votre application d'authentification, ou l'un de vos codes de secours.",
		"authCode":      "Code d'authentification",
		"trustDays":     "Faire confiance à ce navigateur pendant %d jours",
		"verify":        "Vérifier",
		"errBadCode":    "Ce code n'est pas valide.",

		// totp enrolment
		"saveBackupCodes": "Conservez vos codes de secours",
		"backupHint":      "Chaque code fonctionne une seule fois si vous perdez votre authentificateur. Rangez-les en lieu sûr : ils ne seront plus affichés.",
		"savedContinue":   "C'est noté, continuer",
		"mfaRequiredLead": "La double authentification est requise",
		"setupLead":       "Activer la double authentification",
		"scanHint":        "Scannez ce code avec une application d'authentification, ou saisissez la clé à la main, puis tapez le code à 6 chiffres pour confirmer.",
		"qrAlt":           "QR code d'enrôlement",
		"setupKey":        "Clé de configuration",
		"sixDigitCode":    "Code à 6 chiffres",
		"confirm":         "Confirmer",
		"errBadCodeRetry": "Ce code n'est pas valide. Réessayez.",

		// mfa management
		"mfaStatus":         "La double authentification est active. Codes de secours restants : %d sur %d.",
		"replaceAuth":       "Remplacer l'authentificateur",
		"regenCodes":        "Régénérer les codes de secours",
		"turnOffMfa":        "Désactiver la double authentification",
		"mfaRequiredNote":   "La double authentification est requise par votre organisation et ne peut pas être désactivée.",
		"errMfaRequiredOff": "La double authentification est requise et ne peut pas être désactivée.",
		"trustedBrowsers":   "Navigateurs de confiance",
		"untilDate":         "jusqu'au %s",
		"revoke":            "Révoquer",
		"revokeAll":         "Révoquer tous les navigateurs de confiance",

		// preference switchers
		"schemeAuto":  "Suivre le système",
		"schemeLight": "Clair",
		"schemeDark":  "Sombre",

		// user button menu
		"profile":      "Profil",
		"languages":    "Langues",
		"colorScheme":  "Apparence",
		"tenant":       "Tenant",
		"applications": "Applications",

		// profile photo
		"changePhoto":   "Changer la photo",
		"removePhoto":   "Retirer la photo",
		"errAvatarType": "Utilisez une image png, jpeg ou webp",
		"errAvatarSize": "Gardez la photo sous 200 Kio",
	},
}
