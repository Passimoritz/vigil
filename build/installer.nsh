; Vigil – eigene Installer-Teile (eingebunden ueber "nsis.include" in package.json)
;
; 1. Wartungsseite: Ist Vigil schon installiert, fragt der Installer zuerst, was passieren soll:
;    Reparieren / Aktualisieren (Einstellungen und Ergebnisse bleiben) oder Entfernen.
; 2. Schneller Abschluss: "Vigil jetzt starten" uebergibt den Start an cmd.exe (unsichtbar), damit das Setup
;    nicht auf die Windows-Pruefung der neuen Vigil.exe wartet (sonst viele Sekunden nach "Fertig stellen").
; Die Datei muss als UTF-8 MIT BOM gespeichert sein, sonst liest NSIS die Umlaute falsch.

!ifndef BUILD_UNINSTALLER
  !include nsDialogs.nsh
  !include LogicLib.nsh
  !include WordFunc.nsh

  ; Gleiche Schluessel wie electron-builder (multiUser.nsh), dort erst nach diesem Include definiert
  !define vgUNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTALL_APP_KEY}"
  !define vgINST_KEY "Software\${APP_GUID}"

  Var vgOldVersion
  Var vgOldDir
  Var vgOldUninst
  Var vgRadioRepair
  Var vgRadioRemove
  Var vgCmp

  ; Die Seite und ihre Funktionen werden erst dort eingesetzt, wo electron-builder die Seiten aufbaut
  ; (assistedInstaller.nsh) – dann sind MUI2, StdUtils und isUpdated schon geladen.
  !macro customWelcomePage
    Page custom vgMaintCreate vgMaintLeave

  Function vgReadExisting
    ReadRegStr $vgOldVersion HKCU "${vgUNINST_KEY}" "DisplayVersion"
    ReadRegStr $vgOldUninst HKCU "${vgUNINST_KEY}" "UninstallString"
    ReadRegStr $vgOldDir HKCU "${vgINST_KEY}" "InstallLocation"
    ${If} $vgOldUninst == ""
      ReadRegStr $vgOldVersion HKLM "${vgUNINST_KEY}" "DisplayVersion"
      ReadRegStr $vgOldUninst HKLM "${vgUNINST_KEY}" "UninstallString"
      ReadRegStr $vgOldDir HKLM "${vgINST_KEY}" "InstallLocation"
    ${EndIf}
  FunctionEnd

  Function vgMaintCreate
    Call vgReadExisting
    ; Nichts installiert oder automatisches Update: Seite ueberspringen
    ${If} $vgOldUninst == ""
      Abort
    ${EndIf}
    ${If} ${isUpdated}
      Abort
    ${EndIf}
    ${VersionCompare} "${VERSION}" "$vgOldVersion" $vgCmp

    !insertmacro MUI_HEADER_TEXT "Vigil ist bereits installiert" "Version $vgOldVersion in $vgOldDir"
    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
      Abort
    ${EndIf}

    ${If} $vgCmp == 0
      ${NSD_CreateLabel} 0 0 100% 28u "Diese Version (${VERSION}) ist schon installiert. Was möchtest du tun?"
    ${ElseIf} $vgCmp == 1
      ${NSD_CreateLabel} 0 0 100% 28u "Installiert ist Version $vgOldVersion. Dieses Setup bringt Version ${VERSION}. Was möchtest du tun?"
    ${Else}
      ${NSD_CreateLabel} 0 0 100% 28u "Installiert ist die neuere Version $vgOldVersion. Dieses Setup würde auf ${VERSION} zurückgehen. Was möchtest du tun?"
    ${EndIf}
    Pop $0

    ${If} $vgCmp == 0
      ${NSD_CreateRadioButton} 10u 34u 95% 12u "&Reparieren – Programmdateien neu schreiben"
    ${ElseIf} $vgCmp == 1
      ${NSD_CreateRadioButton} 10u 34u 95% 12u "&Aktualisieren auf Version ${VERSION}"
    ${Else}
      ${NSD_CreateRadioButton} 10u 34u 95% 12u "&Trotzdem Version ${VERSION} installieren"
    ${EndIf}
    Pop $vgRadioRepair
    ${NSD_CreateLabel} 24u 47u 90% 20u "Einstellungen, Zugangsdaten, Verlauf und Ergebnisse bleiben erhalten. Der Ordner bleibt derselbe."
    Pop $0

    ${NSD_CreateRadioButton} 10u 72u 95% 12u "&Entfernen – Vigil deinstallieren"
    Pop $vgRadioRemove
    ${NSD_CreateLabel} 24u 85u 90% 20u "Startet die Deinstallation. Deine Daten (Einstellungen, Ergebnisse) bleiben dabei auf dem Rechner, bis du sie selbst löschst."
    Pop $0

    ${NSD_Check} $vgRadioRepair
    nsDialogs::Show
  FunctionEnd

  Function vgMaintLeave
    ${NSD_GetState} $vgRadioRemove $0
    ${If} $0 == ${BST_CHECKED}
      ; Deinstallation des vorhandenen Programms starten, Setup danach beenden
      HideWindow
      ExecWait '$vgOldUninst' $1
      Quit
    ${EndIf}
    ; Reparieren/Aktualisieren: vorhandenen Ordner beibehalten
    ${If} $vgOldDir != ""
      StrCpy $INSTDIR $vgOldDir
    ${EndIf}
  FunctionEnd
  !macroend

  ; Eigene Fertig-Seite: startet Vigil direkt, das Setup schliesst sofort
  !macro customFinishPage
    Function vgStartApp
      ${If} ${UAC_IsInnerInstance}
        ; Setup laeuft mit Adminrechten: Vigil trotzdem als normaler Benutzer starten
        ${StdUtils.ExecShellAsUser} $0 "$launchLink" "open" ""
      ${Else}
        ; Nicht direkt starten: Beim ersten Start einer neuen, unsignierten Vigil.exe prueft Windows
        ; (Smart App Control / Defender) die Datei, und der startende Prozess – das Setup – wartet so
        ; lange. Deshalb uebernimmt das signierte cmd.exe unsichtbar den Start, das Setup schliesst sofort.
        ; Die Pruefung durch Windows findet trotzdem ganz normal statt.
        ExecShell "open" "$SYSDIR\cmd.exe" '/d /c start "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"' SW_HIDE
      ${EndIf}
    FunctionEnd
    !define MUI_FINISHPAGE_RUN
    !define MUI_FINISHPAGE_RUN_TEXT "Vigil jetzt starten"
    !define MUI_FINISHPAGE_RUN_FUNCTION "vgStartApp"
    !insertmacro MUI_PAGE_FINISH
  !macroend
!endif
