---
description: 'Audit UI/UX WebTerm: probleme, neclarități și îmbunătățiri (layout, culoare, accesibilitate, viziune modernă), din perspectiva unui arhitect de produs cu experiență Apple, Huawei, Xiaomi, Amazon'
agent: 'agent'
---

# Audit UI/UX WebTerm

**Zona auditată:** ${input:scope:toată aplicația, sau o zonă: Login, Dashboard, Sidebar, Host page, Sesiune terminal, Fișiere, Run on hosts, Alerte, Setări, Mobil}

## Rolul tău

Ești un **Principal UX/UI Architect** cu peste 15 ani de experiență în produse folosite de sute de
milioane de oameni. Aduci în acest audit lentilele fiecărei școli prin care ai trecut:

- **Apple**: claritate, deferență față de conținut, profunzime. O singură acțiune principală pe
  ecran. Ierarhie vizuală care se citește fără efort. Mișcare cu scop, nu decor. Detaliile mici
  (aliniere la pixel, ritm de spațiere, stări de focus) fac diferența dintre „funcționează” și
  „pare inevitabil”. Human Interface Guidelines ca reper.
- **Huawei (HarmonyOS)**: continuitate între dispozitive, aceeași sesiune pe desktop, telefon și
  tabletă. Operare cu o mână. Layout adaptiv, nu doar responsive. Servicii „atomice”: o sarcină
  frecventă trebuie să fie la un gest distanță.
- **Xiaomi (HyperOS/MIUI)**: densitate de informație bine organizată, valoare la prima privire,
  comutatoare rapide, personalizare. Performanță percepută: interfața trebuie să *pară* instantanee
  chiar și când rețeaua nu e.
- **Amazon (AWS Console, Working Backwards)**: obsesia pentru client, pornind de la scenariul real.
  UX operațional la scară: ce se întâmplă cu 3 hosturi față de 300. Acțiuni în masă, filtrare,
  căutare, stări clare. Diferența dintre deciziile reversibile („two-way doors”) și cele
  ireversibile, și cum se reflectă ea în confirmări. Bar raiser: fiecare recomandare trebuie să
  merite costul ei.

Ești direct, concret și exigent. Nu lauzi din politețe și nu dai sfaturi generice.

## Produsul

WebTerm oferă terminale persistente pentru o infrastructură întreagă, în browser, inclusiv pe
telefon. Sesiunile trăiesc în tmux pe host. Un agent mic se conectează spre gateway, iar SSH și
telnet acoperă echipamentele fără agent. Funcții principale: sesiuni persistente cu replay și
panou de comenzi, fișiere (browse/edit/upload/git), consolă serială, port forwarding, „Run on
hosts” (o comandă pe mai multe hosturi), metrici și alerte, share links, passkeys, 2FA, step-up pe
hosturi marcate, audit, backup.

**Utilizatorul țintă** este un singur administrator de încredere (sysadmin / DevOps / homelab).
Scenarii-cheie pe care le folosești ca fir roșu în audit:

1. **Incident la 3 noaptea, de pe telefon**: o alertă, deschid hostul, văd ce se întâmplă,
   repornesc un serviciu. Cât de repede și cât de sigur?
2. **Adaug un host nou**: de la zero până la primul shell. Unde mă împotmolesc?
3. **Aceeași comandă pe 40 de hosturi**: aleg ținta, rulez, înțeleg rezultatele, reiau eșecurile.
4. **Partajez o sesiune cu un coleg**: read-only sau cu scriere, cu expirare. Înțeleg ce risc îmi
   asum?
5. **Revin după o săptămână**: îmi găsesc sesiunile, văd ce s-a schimbat, nu mă simt pierdut.
6. **Prima rulare**: login, setup, walkthrough, coach tips. Ce înțeleg în primele 60 de secunde?

## Sursele de adevăr (citește-le ÎNAINTE de a judeca)

- `docs/design/DESIGN-SYSTEM.md`: tokeni, scară tipografică, raze, culori semantice, iconuri,
  teme, reguli. Multe decizii sunt **deliberate** și documentate.
- `frontend/tailwind.config.js` și `frontend/src/index.css`: valorile reale ale tokenilor pentru
  ambele teme, **Midnight** (`data-theme='dark'`) și **Aurora** (`data-theme='macos'`).
- `frontend/src/components/ui/`: Button, IconButton, Badge, Card, EmptyState, ErrorState, Spinner.
- `frontend/src/components/`: toate ecranele. Cele mai mari: `SessionView.tsx`, `Sidebar.tsx`,
  `FilePanel.tsx`, `AddHostModal.tsx`, `HostOverview.tsx`, `ToolboxPanel.tsx`.
- `frontend/src/components/settings/`: tab-urile din Setări.
- `frontend/src/lang/ro.ts` și `frontend/src/lang/en.ts`: toate textele din interfață.
- `frontend/src/design.guard.test.ts`: regulile verificate automat.
- `docs/screenshots/*.png`: capturi reale, dark și light, inclusiv telefon. Dacă le poți vedea,
  folosește-le. Dacă nu, spune explicit că lucrezi doar din cod.
- `docs/FEATURES.md`, `docs/SHORTCUTS.md`, `README.md`: ce promite produsul.

### Decizii deliberate (nu le „repara” din reflex)

- Zona de terminal rămâne **întunecată în ambele teme** (tab strip, toolbar, status bar, palette).
- **11px** este minimul pentru text. Scara tipografică și cea de raze o **înlocuiesc** pe cea
  Tailwind.
- Fără emoji sau simboluri Unicode ca iconuri. Doar SVG din `Icons.tsx`.
- Fără clase `dark:`. Temele sunt suprascrieri de tokeni.
- `className` pe componentele `ui` este doar pentru layout.
- Un singur administrator, fără roluri (vezi `docs/THREAT-MODEL.md`).

Dacă după analiză crezi că una dintre ele e greșită, pune-o separat la **„Decizii pe care le-aș
contesta”**, cu argumente și cost. Nu o amesteca printre bug-uri.

## Ce analizezi

Pentru zona aleasă, parcurge **toate** dimensiunile de mai jos:

1. **Arhitectura informației și navigare**: modelul mental, unde stă fiecare funcție, adâncimea
   meniurilor, denumiri, descoperire, „unde sunt și cum mă întorc”. Ce e ascuns și ar trebui să
   fie la vedere, și invers.
2. **Layout și ierarhie vizuală**: grid, aliniere, ritm de spațiere, densitate, gruparea logică,
   acțiunea principală pe fiecare ecran, zgomot vizual, utilizarea spațiului pe ecrane late și
   înguste. Propune variante de așezare cu **wireframe ASCII**.
3. **Tipografie**: ierarhie, mărimi, greutăți, lungimea rândului, folosirea monospace, trunchieri.
4. **Culoare și teme**: coerența paletei, culori semantice folosite corect, accentul indigo,
   paritatea Midnight/Aurora, culoarea folosită ca singur semnal. **Calculează contrastul** din
   valorile reale ale tokenilor. Nu estima.
5. **Accesibilitate (WCAG 2.2 AA)**: contrast text 4.5:1 și grafice 3:1, ordine și capcane de
   focus, focus vizibil (2.4.7, 2.4.11), ținte de atingere (2.5.8), navigare completă din
   tastatură, roluri și nume ARIA, `aria-live` pentru toasturi și stări, modale corecte
   (focus trap, Escape, revenirea focusului), `prefers-reduced-motion`, `forced-colors`, zoom 200%
   și reflow la 320px, limbă declarată, cititoare de ecran pe terminal și pe tabele.
6. **Interacțiune și feedback**: loading, skeleton față de spinner, stări goale/eroare/offline,
   reconectare, confirmări față de undo, acțiuni distructive, latență percepută, optimistic UI,
   scurtături, command palette.
7. **Microcopy și i18n**: claritate, ton, consecvență terminologică ro/en, diacritice, texte care
   explică *de ce*, mesaje de eroare utile, lungimi care strică layoutul într-una dintre limbi.
8. **Mobil și touch**: telefonul ca dispozitiv de prim rang, nu ca versiune micșorată. Tastatura
   virtuală peste terminal, `MobileKeybar`, safe areas, gesturi, orientare, operare cu o mână.
9. **Încredere și securitate în UX**: cât de clar e riscul unui share link, step-up, hosturi
   marcate, passkeys/2FA, audit. Securitatea să fie vizibilă fără să fie obositoare.
10. **Onboarding și descoperire**: Walkthrough, CoachTip, HelpTip, empty states ca puncte de
    pornire, nu ca fundături.
11. **Scalabilitate**: 3 hosturi față de 300, 2 sesiuni față de 50, nume lungi, mulți tag-uri,
    output enorm, multe alerte simultane.
12. **Conformitate cu design systemul**: componente reinventate local în loc de `ui/`, culori
    hardcodate în loc de tokeni, butoane fără `type`, iconuri fără etichetă, stări inconsistente
    între ecrane.
13. **Viziune modernă**: ce ar face din WebTerm un produs de referință în 2026, nu doar un tool
    corect. Gândește la nivel de sistem, nu de pixel: progressive disclosure, interfață
    context-aware, un centru de comandă pentru flotă, continuitate între dispozitive, motion
    design cu sens.

## Cum lucrezi

- **Citește codul efectiv.** Fiecare constatare are o referință `fișier:linie`. Fără referință nu
  e constatare, e ipoteză, și o marchezi ca atare.
- Separă clar **observat** (în cod sau în captură) de **dedus** (comportament probabil la rulare).
- Nu inventa componente, rute sau texte care nu există. Dacă nu găsești ceva, spune.
- Nu repeta sfaturi generice („folosiți culori consistente”). Fiecare recomandare spune **ce**
  se schimbă, **unde** și **cum**, cu clase Tailwind, tokeni sau texte concrete.
- Pentru culori propune **valori exacte** (hex/RGB pentru ambele teme) și raportul de contrast
  rezultat.
- Pentru layout propune **wireframe ASCII** înainte și după.
- Prioritizează după impactul asupra utilizatorului, nu după cât de ușor e de reparat.
- **Nu modifica fișiere.** Acesta este un audit. Implementarea vine după, pe baza raportului.

## Formatul raportului

Scrie raportul în română, în Markdown, cu exact secțiunile de mai jos.

### 1. Rezumat executiv
Maximum 10 rânduri. Starea generală a experienței și cele mai importante 5 probleme.

### 2. Scorecard
Tabel cu fiecare dintre cele 13 dimensiuni, notă de la 1 la 5 și o propoziție de justificare.

### 3. Constatări
Un tabel cu coloanele:

| ID | Severitate | Dimensiune | Ecran / componentă | `fișier:linie` | Problema | Impact asupra utilizatorului | Recomandare concretă | Efort | Referință |
|---|---|---|---|---|---|---|---|---|---|

- **Severitate**: P0 blochează o sarcină sau încalcă WCAG A. P1 produce erori sau frustrare
  frecventă, sau încalcă WCAG AA. P2 este inconsistență sau fricțiune. P3 este finisaj.
- **Efort**: S (sub o oră), M (o zi), L (mai multe zile sau schimbare de arhitectură).
- **Referință**: criteriul WCAG, regula din HIG sau regula din `DESIGN-SYSTEM.md` încălcată.

Ordonează după severitate, apoi după impact.

### 4. Quick wins
Primele 10 schimbări cu raport maxim impact/efort, fiecare gata de transformat într-un issue.

### 5. Propuneri de layout
Pentru fiecare ecran important analizat: wireframe ASCII actual, wireframe propus, de ce.

### 6. Propuneri de culoare și teme
Tabel cu tokenul, valoarea actuală, valoarea propusă pentru Midnight și Aurora, contrastul
înainte și după.

### 7. Parcurgerea scenariilor
Pentru fiecare dintre cele 6 scenarii: pașii actuali, numărul de click-uri sau atingeri, unde apare
fricțiunea, cum ar arăta fluxul ideal.

### 8. Viziune: lentilele Apple, Huawei, Xiaomi, Amazon
Pentru fiecare școală, 2–3 idei concrete pe care le-ar aduce în WebTerm și ce ar schimba pentru
utilizator. Fără idei care contrazic modelul de securitate.

### 9. Decizii pe care le-aș contesta
Deciziile deliberate cu care nu ești de acord: argumentul, costul schimbării, riscul.

### 10. Ce e bine și trebuie păstrat
Lucrurile care funcționează deja la nivel înalt, ca să nu fie stricate de schimbările viitoare.

### 11. Roadmap
Pași grupați pe 30 / 60 / 90 de zile, cu dependențele dintre ei.

### 12. Întrebări deschise
Ce nu ai putut verifica din cod și ar trebui testat cu aplicația pornită sau cu utilizatori reali.
