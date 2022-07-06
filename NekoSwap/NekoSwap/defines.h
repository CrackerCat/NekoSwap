#pragma once

namespace Defines
{
	// win32k!ext_ms_win_core_win32k_fulluser_l1
	enum FunctionList
	{
		NtUserAcquireIAMKey,
		NtUserAcquireInteractiveControlBackgroundAccess,
		NtUserAddClipboardFormatListener,
		NtUserAlterWindowStyle,
		NtUserAssociateInputContext,
		NtUserAttachThreadInput,
		NtUserAutoPromoteMouseInPointer,
		NtUserEnableMouseInPointerForWindow,
		NtUserAutoRotateScreen,
		NtUserBeginLayoutUpdate,
		NtUserBeginPaint,
		NtUserBitBltSysBmp,
		NtUserBlockInput,
		NtUserBroadcastThemeChangeEvent,
		NtUserBuildHimcList,
		NtUserBuildHwndList,
		NtUserBuildNameList,
		NtUserBuildPropList,
		NtUserCalcMenuBar,
		NtUserCalculatePopupWindowPosition,
		NtUserCallHwnd,
		NtUserCallHwndLock,
		NtUserCallHwndLockSafe,
		NtUserCallHwndOpt,
		NtUserCallHwndParam,
		NtUserCallHwndParamLock,
		NtUserCallHwndParamLockSafe,
		NtUserCallHwndSafe,
		NtUserCallMsgFilter,
		NtUserCallNextHookEx,
		NtUserCanBrokerForceForeground,
		NtUserChangeClipboardChain,
		NtUserChangeWindowMessageFilterEx,
		NtUserCheckAccessForIntegrityLevel,
		NtUserCheckMenuItem,
		NtUserCheckProcessForClipboardAccess,
		NtUserCheckWindowThreadDesktop,
		NtUserChildWindowFromPointEx,
		NtUserClearForeground,
		NtUserCloseClipboard,
		NtUserCompositionInputSinkLuidFromPoint,
		NtUserCompositionInputSinkViewInstanceIdFromPoint,
		NtUserConfirmResizeCommit,
		NtUserConsoleControl,
		NtUserConvertMemHandle,
		NtUserCopyAcceleratorTable,
		NtUserCountClipboardFormats,
		NtUserCreateAcceleratorTable,
		NtUserCreateCaret,
		NtUserCreateEmptyCursorObject,
		NtUserCreateInputContext,
		NtUserCreateLocalMemHandle,
		NtUserCreateWindowEx,
		NtUserCreateWindowGroup,
		NtUserCtxDisplayIOCtl,
		NtUserDdeInitialize,
		NtUserDeferWindowDpiChanges,
		NtUserDeferWindowPosAndBand,
		NtUserDefSetText,
		NtUserDeleteMenu,
		NtUserDeleteWindowGroup,
		NtUserDestroyAcceleratorTable,
		NtUserDestroyCursor,
		NtUserDestroyInputContext,
		NtUserDestroyMenu,
		NtUserDestroyWindow,
		NtUserDisableImmersiveOwner,
		NtUserDisableProcessWindowFiltering,
		NtUserDisableThreadIme,
		NtUserDiscardPointerFrameMessages,
		NtUserDispatchMessage,
		NtUserDoSoundConnect,
		NtUserDoSoundDisconnect,
		NtUserDragDetect,
		NtUserDragObject,
		NtUserDrawAnimatedRects,
		NtUserDrawCaption,
		NtUserDrawCaptionTemp,
		NtUserDrawIconEx,
		NtUserDrawMenuBarTemp,
		NtUserDwmGetRemoteSessionOcclusionEvent,
		NtUserDwmGetRemoteSessionOcclusionState,
		NtUserDwmValidateWindow,
		NtUserEmptyClipboard,
		NtUserEnableChildWindowDpiMessage,
		NtUserEnableIAMAccess,
		NtUserEnableMenuItem,
		NtUserEnableMouseInputForCursorSuppression,
		NtUserEnableNonClientDpiScaling,
		NtUserEnableScrollBar,
		NtUserEnableSoftwareCursorForScreenCapture,
		NtUserEnableWindowGDIScaledDpiMessage,
		NtUserEnableWindowGroupPolicy,
		NtUserEnableWindowResizeOptimization,
		NtUserEndDeferWindowPosEx,
		NtUserEndMenu,
		NtUserEndPaint,
		NtUserEvent,
		NtUserExcludeUpdateRgn,
		NtUserFillWindow,
		NtUserFindExistingCursorIcon,
		NtUserFindWindowEx,
		NtUserFlashWindowEx,
		NtUserForceWindowToDpiForTest,
		NtUserFrostCrashedWindow,
		NtUserGetActiveProcessesDpis,
		NtUserGetAltTabInfo,
		NtUserGetAncestor,
		NtUserGetAppImeLevel,
		NtUserGetAtomName,
		NtUserGetAutoRotationState,
		NtUserGetCaretBlinkTime,
		NtUserGetCaretPos,
		NtUserGetCIMSSM,
		NtUserGetClassInfoEx,
		NtUserGetClassName,
		NtUserGetClipboardAccessToken,
		NtUserGetClipboardData,
		NtUserGetClipboardFormatName,
		NtUserGetClipboardOwner,
		NtUserGetClipboardSequenceNumber,
		NtUserGetClipboardViewer,
		NtUserGetComboBoxInfo,
		NtUserGetControlBrush,
		NtUserGetControlColor,
		NtUserGetCPD,
		NtUserGetCurrentDpiInfoForWindow,
		NtUserGetCurrentInputMessageSource,
		NtUserGetCursor,
		NtUserGetCursorFrameInfo,
		NtUserGetCursorInfo,
		NtUserGetDCEx,
		NtUserGetDesktopID,
		NtUserGetDisplayAutoRotationPreferences,
		NtUserGetDisplayAutoRotationPreferencesByProcessId,
		NtUserGetDManipHookInitFunction,
		NtUserGetDpiForCurrentProcess,
		NtUserGetForegroundWindow,
		NtUserGetGestureConfig,
		NtUserGetGestureExtArgs,
		NtUserGetGestureInfo,
		NtUserGetGuiResources,
		NtUserGetGUIThreadInfo,
		NtUserGetHimetricScaleFactorFromPixelLocation,
		NtUserGetIconInfo,
		NtUserGetIconSize,
		NtUserGetImeHotKey,
		NtUserGetImeInfoEx,
		NtUserGetInputLocaleInfo,
		NtUserGetInteractiveControlDeviceInfo,
		NtUserGetInteractiveControlInfo,
		NtUserGetInteractiveCtrlSupportedWaveforms,
		NtUserGetInternalWindowPos,
		NtUserGetKeyboardLayoutName,
		NtUserGetKeyNameText,
		NtUserGetLayeredWindowAttributes,
		NtUserGetListBoxInfo,
		NtUserGetMenuBarInfo,
		NtUserGetMenuIndex,
		NtUserGetMenuItemRect,
		NtUserGetMessage,
		NtUserGetMouseMovePointsEx,
		NtUserGetOemBitmapSize,
		NtUserGetOpenClipboardWindow,
		NtUserGetOwnerTransformedMonitorRect,
		NtUserGetPhysicalDeviceRect,
		NtUserGetPointerDeviceCursors,
		NtUserGetPriorityClipboardFormat,
		NtUserGetProcessUIContextInformation,
		NtUserGetProp,
		NtUserGetQueueStatusReadonly,
		NtUserGetRawInputBuffer,
		NtUserGetRawInputData,
		NtUserGetRawInputDeviceInfo,
		NtUserGetRawInputDeviceList,
		NtUserGetRegisteredRawInputDevices,
		NtUserGetRequiredCursorSizes,
		NtUserGetScrollBarInfo,
		NtUserGetSystemMenu,
		NtUserGetTitleBarInfo,
		NtUserGetTopLevelWindow,
		NtUserGetTouchInputInfo,
		NtUserGetTouchValidationStatus,
		NtUserGetUpdatedClipboardFormats,
		NtUserGetUpdateRect,
		NtUserGetUpdateRgn,
		NtUserGetWindowBand,
		NtUserGetWindowCompositionAttribute,
		NtUserGetWindowCompositionInfo,
		NtUserGetWindowDC,
		NtUserGetWindowDisplayAffinity,
		NtUserGetWindowFeedbackSetting,
		NtUserGetWindowGroupId,
		NtUserGetWindowMinimizeRect,
		NtUserGetWindowPlacement,
		NtUserGetWindowProcessHandle,
		NtUserGetWindowRgnEx,
		NtUserGetWOWClass,
		NtUserGhostWindowFromHungWindow,
		NtUserHardErrorControl,
		NtUserHideCaret,
		NtUserHidePointerContactVisualization,
		NtUserHiliteMenuItem,
		NtUserHungWindowFromGhostWindow,
		NtUserHwndQueryRedirectionInfo,
		NtUserHwndSetRedirectionInfo,
		NtUserImpersonateDdeClientWindow,
		NtUserInheritWindowMonitor,
		NtUserInitializeClientPfnArrays,
		NtUserInitializeTouchInjection,
		NtUserInitTask,
		NtUserInjectGesture,
		NtUserInjectTouchInput,
		NtUserInteractiveControlQueryUsage,
		NtUserInternalGetWindowIcon,
		NtUserInternalGetWindowText,
		NtUserInvalidateRect,
		NtUserInvalidateRgn,
		NtUserIsChildWindowDpiMessageEnabled,
		NtUserIsClipboardFormatAvailable,
		NtUserIsMouseInputEnabled,
		NtUserIsNonClientDpiScalingEnabled,
		NtUserIsTopLevelWindow,
		NtUserIsTouchWindow,
		NtUserIsWindowBroadcastingDpiToChildren,
		NtUserIsWindowGDIScaledDpiMessageEnabled,
		NtUserKillTimer,
		NtUserLayoutCompleted,
		NtUserLinkDpiCursor,
		NtUserLockWindowStation,
		NtUserLockWindowUpdate,
		NtUserLockWorkStation,
		NtUserLogicalToPerMonitorDPIPhysicalPoint,
		NtUserLogicalToPhysicalDpiPointForWindow,
		NtUserLogicalToPhysicalPoint,
		NtUserMagControl,
		NtUserMagGetContextInformation,
		NtUserMagSetContextInformation,
		NtUserMenuItemFromPoint,
		NtUserMessageCall,
		NtUserMinMaximize,
		NtUserMNDragLeave,
		NtUserMNDragOver,
		NtUserModifyUserStartupInfoFlags,
		NtUserModifyWindowTouchCapability,
		NtUserMoveWindow,
		NtUserMsgWaitForMultipleObjectsEx,
		NtUserNavigateFocus,
		NtUserNotifyIMEStatus,
		NtUserNotifyProcessCreate,
		NtUserNotifyWinEvent,
		NtUserOpenClipboard,
		NtUserOpenDesktop,
		NtUserOpenThreadDesktop,
		NtUserOpenWindowStation,
		NtUserPaintDesktop,
		NtUserPaintMenuBar,
		NtUserPaintMonitor,
		NtUserPeekMessage,
		NtUserPerMonitorDPIPhysicalToLogicalPoint,
		NtUserPhysicalToLogicalDpiPointForWindow,
		NtUserPhysicalToLogicalPoint,
		NtUserPostMessage,
		NtUserPostThreadMessage,
		NtUserPrintWindow,
		NtUserProcessConnect,
		NtUserProcessInkFeedbackCommand,
		NtUserPromoteMouseInPointer,
		NtUserPromotePointer,
		NtUserQueryBSDRWindow,
		NtUserQueryInformationThread,
		NtUserQueryInputContext,
		NtUserQuerySendMessage,
		NtUserQueryWindow,
		NtUserRealChildWindowFromPoint,
		NtUserRealInternalGetMessage,
		NtUserRealWaitMessageEx,
		NtUserRedrawWindow,
		NtUserRegisterBSDRWindow,
		NtUserRegisterClassExWOW,
		NtUserRegisterDManipHook,
		NtUserRegisterEdgy,
		NtUserRegisterErrorReportingDialog,
		NtUserRegisterHotKey,
		NtUserRegisterPointerDeviceNotifications,
		NtUserRegisterRawInputDevices,
		NtUserRegisterServicesProcess,
		NtUserRegisterShellPTPListener,
		NtUserRegisterTasklist,
		NtUserRegisterTouchHitTestingWindow,
		NtUserRegisterUserApiHook,
		NtUserRegisterWindowMessage,
		NtUserRemoteConnect,
		NtUserRemoteRedrawRectangle,
		NtUserRemoteRedrawScreen,
		NtUserRemoteStopScreenUpdates,
		NtUserRemoveClipboardFormatListener,
		NtUserRemoveMenu,
		NtUserRemoveProp,
		NtUserRequestMoveSizeOperation,
		NtUserResolveDesktopForWOW,
		NtUserRestoreWindowDpiChanges,
		NtUserSBGetParms,
		NtUserScrollDC,
		NtUserScrollWindowEx,
		NtUserSelectPalette,
		NtUserSendEventMessage,
		NtUserSendInput,
		NtUserSendInteractiveControlHapticsReport,
		NtUserSetActivationFilter,
		NtUserSetActiveProcessForMonitor,
		NtUserSetActiveWindow,
		NtUserSetAppImeLevel,
		NtUserSetAutoRotation,
		NtUserSetBridgeWindowChild,
		NtUserSetBrokeredForeground,
		NtUserSetCalibrationData,
		NtUserSetCapture,
		NtUserSetChildWindowNoActivate,
		NtUserSetClassLong,
		NtUserSetClassWord,
		NtUserSetClipboardData,
		NtUserSetClipboardViewer,
		NtUserSetCoreWindow,
		NtUserSetCoreWindowPartner,
		NtUserSetCursor,
		NtUserSetCursorContents,
		NtUserSetCursorIconData,
		NtUserSetDesktopColorTransform,
		NtUserSetMagnificationDesktopMagnifierOffsetsDWMUpdated,
		NtUserSetFullscreenMagnifierOffsetsDWMUpdated,
		NtUserSetDialogControlDpiChangeBehavior,
		NtUserSetDisplayAutoRotationPreferences,
		NtUserSetDisplayMapping,
		NtUserSetFallbackForeground,
		NtUserSetFocus,
		NtUserSetForegroundWindowForApplication,
		NtUserSetGestureConfig,
		NtUserSetImeHotKey,
		NtUserSetImeInfoEx,
		NtUserSetImeOwnerWindow,
		NtUserSetInformationThread,
		NtUserSetInteractiveControlFocus,
		NtUserSetInteractiveCtrlRotationAngle,
		NtUserSetInternalWindowPos,
		NtUserSetKeyboardState,
		NtUserSetLayeredWindowAttributes,
		NtUserSetMenu,
		NtUserSetMenuContextHelpId,
		NtUserSetMenuDefaultItem,
		NtUserSetMenuFlagRtoL,
		NtUserSetMirrorRendering,
		NtUserSetObjectInformation,
		NtUserSetParent,
		NtUserSetProcessInteractionFlags,
		NtUserSetProcessRestrictionExemption,
		NtUserSetProcessUIAccessZorder,
		NtUserSetProp,
		NtUserSetScrollInfo,
		NtUserSetSensorPresence,
		NtUserSetShellWindowEx,
		NtUserSetSystemCursor,
		NtUserSetSystemMenu,
		NtUserSetSystemTimer,
		NtUserSetTargetForResourceBrokering,
		NtUserSetThreadDesktop,
		NtUserSetThreadInputBlocked,
		NtUserSetThreadLayoutHandles,
		NtUserSetThreadState,
		NtUserSetTimer,
		NtUserSetWindowArrangement,
		NtUserSetWindowBand,
		NtUserSetWindowCompositionAttribute,
		NtUserSetWindowCompositionTransition,
		NtUserSetWindowDisplayAffinity,
		NtUserSetWindowFeedbackSetting,
		NtUserSetWindowFNID,
		NtUserSetWindowGroup,
		NtUserSetWindowLong,
		NtUserSetWindowPlacement,
		NtUserSetWindowPos,
		NtUserSetWindowRgn,
		NtUserSetWindowRgnEx,
		NtUserSetWindowsHookAW,
		NtUserSetWindowsHookEx,
		NtUserSetWindowShowState,
		NtUserSetWindowStationUser,
		NtUserSetWindowWord,
		NtUserSetWinEventHook,
		NtUserShowCaret,
		NtUserShowCursor,
		NtUserShowScrollBar,
		NtUserShowSystemCursor,
		NtUserShowWindow,
		NtUserShowWindowAsync,
		NtUserShutdownBlockReasonCreate,
		NtUserShutdownBlockReasonQuery,
		NtUserShutdownReasonDestroy,
		NtUserSignalRedirectionStartComplete,
		NtUserSlicerControl,
		NtUserSoundSentry,
		NtUserSwitchDesktop,
		NtUserSystemParametersInfoForDpi,
		NtUserTestForInteractiveUser,
		NtUserThunkedMenuInfo,
		NtUserThunkedMenuItemInfo,
		NtUserTrackMouseEvent,
		NtUserTrackPopupMenuEx,
		NtUserTransformPoint,
		NtUserTransformRect,
		NtUserTranslateAccelerator,
		NtUserTranslateMessage,
		NtUserUnhookWindowsHookEx,
		NtUserUnhookWinEvent,
		NtUserUnlockWindowStation,
		NtUserUnregisterClass,
		NtUserUnregisterHotKey,
		NtUserUnregisterUserApiHook,
		NtUserUpdateDefaultDesktopThumbnail,
		NtUserUpdateInputContext,
		NtUserUpdateInstance,
		NtUserUpdateLayeredWindow,
		NtUserUpdateWindowInputSinkHints,
		NtUserUpdateWindowTrackingInfo,
		NtUserUserHandleGrantAccess,
		NtUserValidateRect,
		NtUserValidateTimerCallback,
		NtUserWaitAvailableMessageEx,
		NtUserWaitForInputIdle,
		NtUserWaitForMsgAndEvent,
		NtUserWaitForRedirectionStartComplete,
		NtUserWaitMessage,
		NtUserWindowFromDC,
		NtUserWindowFromPhysicalPoint,
		NtUserWindowFromPoint,
		NtUserWOWCleanup,
		NtUserYieldTask
	};

	enum TableList
	{
		ext_ms_win_core_win32k_base_export_l1,
		ext_ms_win_core_win32k_base_export_l1_host,
		ext_ms_win_core_win32k_baseinit_l1,
		ext_ms_win_core_win32k_baseinit_l1_host,
		ext_ms_win_core_win32k_common_export_l1,
		ext_ms_win_core_win32k_common_export_l1_host,
		ext_ms_win_core_win32k_common_input_l1,
		ext_ms_win_core_win32k_common_input_l1_host,
		ext_ms_win_core_win32k_common_inputrim_l1,
		ext_ms_win_core_win32k_common_inputrim_l1_host,
		ext_ms_win_core_win32k_common_user_l1,
		ext_ms_win_core_win32k_common_user_l1_host,
		ext_ms_win_core_win32k_dcomp_l1,
		ext_ms_win_core_win32k_dcomp_l1_host,
		ext_ms_win_core_win32k_ddccigdi_l1,
		ext_ms_win_core_win32k_ddccigdi_l1_host,
		ext_ms_win_core_win32k_dxgdi_l1,
		ext_ms_win_core_win32k_dxgdi_l1_host,
		ext_ms_win_core_win32k_full_export_l1,
		ext_ms_win_core_win32k_full_export_l1_host,
		ext_ms_win_core_win32k_full_float_export_l1,
		ext_ms_win_core_win32k_full_float_export_l1_host,
		ext_ms_win_core_win32k_fulldcompbase_l1,
		ext_ms_win_core_win32k_fulldcompbase_l1_host,
		ext_ms_win_core_win32k_fulldwm_l1,
		ext_ms_win_core_win32k_fulldwm_l1_host,
		ext_ms_win_core_win32k_fullgdi_l1,
		ext_ms_win_core_win32k_fullgdi_l1_host,
		ext_ms_win_core_win32k_fulluser_l1,
		ext_ms_win_core_win32k_fulluser_l1_host,
		ext_ms_win_core_win32k_fulluser64_l1,
		ext_ms_win_core_win32k_fulluser64_l1_host,
		ext_ms_win_core_win32k_fulluserbase_l1,
		ext_ms_win_core_win32k_fulluserbase_l1_host,
		ext_ms_win_core_win32k_gdi_l1,
		ext_ms_win_core_win32k_gdi_l1_host,
		ext_ms_win_core_win32k_input_l1,
		ext_ms_win_core_win32k_input_l1_host,
		ext_ms_win_core_win32k_inputmit_l1,
		ext_ms_win_core_win32k_inputmit_l1_host,
		ext_ms_win_core_win32k_inputrim_l1,
		ext_ms_win_core_win32k_inputrim_l1_host,
		ext_ms_win_core_win32k_mindwm_l1,
		ext_ms_win_core_win32k_mindwm_l1_host,
		ext_ms_win_core_win32k_mininput_l1,
		ext_ms_win_core_win32k_mininput_l1_host,
		ext_ms_win_core_win32k_mininputmit_l1,
		ext_ms_win_core_win32k_mininputmit_l1_host,
		ext_ms_win_core_win32k_mininputmitbase_l1,
		ext_ms_win_core_win32k_mininputmitbase_l1_host,
		ext_ms_win_core_win32k_minuser_l1,
		ext_ms_win_core_win32k_minuser_l1_host,
		ext_ms_win_core_win32k_opmgdi_l1,
		ext_ms_win_core_win32k_opmgdi_l1_host,
		ext_ms_win_core_win32k_user_l1,
		ext_ms_win_core_win32k_user_l1_host,
		ext_ms_win_core_win32k_userdisplay_l1,
		ext_ms_win_core_win32k_userdisplay_l1_host
	};
}