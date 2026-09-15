using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using Windows.Graphics;
using System.Xml.Linq;
using AppControl.PolicyWizard.Core;
using AppControl.PolicyWizard.WinUI.Composition;

namespace AppControl.PolicyWizard.WinUI;

public sealed partial class MainWindow : Window
{
    private readonly Brush _defaultCardBorder;
    private readonly Brush _selectedCardBorder;
    private readonly PolicyWorkflowService _policyWorkflowService =
        PolicyWorkflowFactory.Create();
    private int _currentStep = 1;
    private PolicySourceKind _selectedSourceKind = PolicySourceKind.SignedAndReputable;
    private PolicySourceInfo? _existingPolicy;
    private PolicyConfigurationEditor? _policyConfiguration;
    private PolicyConfigurationSnapshot? _initialPolicyConfiguration;
    private XDocument? _initialPolicyDocument;
    private IReadOnlyList<PolicySemanticChange> _policyChanges = [];
    private bool _updatingPolicyControls;

    public MainWindow()
    {
        InitializeComponent();

        Title = "App Control Policy Wizard";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.SetIcon("Assets/AppIcon.ico");
        SizeToWorkArea();

        _defaultCardBorder = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"];
        _selectedCardBorder = (Brush)Application.Current.Resources["AccentFillColorDefaultBrush"];

        RegisterPolicyControlChangeHandlers();
        ApplySourceDefaults();
        UpdatePolicySourceCards();
        UpdateStep();
    }

    private void SizeToWorkArea()
    {
        DisplayArea? displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Nearest);
        if (displayArea is null)
        {
            AppWindow.Resize(new SizeInt32(960, 640));
            return;
        }

        RectInt32 workArea = displayArea.WorkArea;
        int width = Math.Min(workArea.Width, Math.Min(1100, Math.Max(480, workArea.Width - 48)));
        int height = Math.Min(workArea.Height, Math.Min(720, Math.Max(400, workArea.Height - 48)));
        int x = workArea.X + Math.Max(0, (workArea.Width - width) / 2);
        int y = workArea.Y + Math.Max(0, (workArea.Height - height) / 2);

        AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
    }

    private async void PolicySourceCard_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string source })
        {
            return;
        }

        ValidationInfoBar.IsOpen = false;

        if (source == "Existing Policy")
        {
            await SelectExistingPolicyAsync();
            return;
        }

        _selectedSourceKind = source switch
        {
            "Windows Only" => PolicySourceKind.WindowsOnly,
            _ => PolicySourceKind.SignedAndReputable
        };

        ResetPolicyConfiguration();
        ApplySourceDefaults();
        UpdatePolicySourceCards();
    }

    private async Task SelectExistingPolicyAsync()
    {
        var picker = new FileOpenPicker(AppWindow.Id)
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            CommitButtonText = "Open policy",
            ViewMode = PickerViewMode.List
        };
        picker.FileTypeFilter.Add(".xml");

        var pickedFile = await picker.PickSingleFileAsync();
        if (pickedFile is null)
        {
            return;
        }

        try
        {
            _existingPolicy = _policyWorkflowService.InspectExistingPolicy(pickedFile.Path);
            _selectedSourceKind = PolicySourceKind.ExistingPolicy;
            ResetPolicyConfiguration();
            ExistingPolicyFileName.Text = Path.GetFileName(_existingPolicy.Path);
            ExistingPolicyFileName.Visibility = Visibility.Visible;
            ApplySourceDefaults();
            UpdatePolicySourceCards();
        }
        catch (UnauthorizedAccessException exception)
        {
            ShowSourceError("Windows denied access to the selected policy.", exception);
        }
        catch (InvalidDataException exception)
        {
            ShowSourceError("The selected file is not a valid App Control policy.", exception);
        }
        catch (IOException exception)
        {
            ShowSourceError("The selected policy could not be opened.", exception);
        }
    }

    private void ShowSourceError(string title, Exception exception)
    {
        ValidationInfoBar.Severity = InfoBarSeverity.Error;
        ValidationInfoBar.Title = title;
        ValidationInfoBar.Message = exception.Message;
        ValidationInfoBar.IsOpen = true;
    }

    private void UpdatePolicySourceCards()
    {
        if (SignedReputableCard is null || _defaultCardBorder is null || _selectedCardBorder is null)
        {
            return;
        }

        SetCardSelection(
            SignedReputableCard,
            SignedReputableSelectedIcon,
            SignedReputableSelectionText,
            _selectedSourceKind == PolicySourceKind.SignedAndReputable);
        SetCardSelection(
            WindowsOnlyCard,
            WindowsOnlySelectedIcon,
            WindowsOnlySelectionText,
            _selectedSourceKind == PolicySourceKind.WindowsOnly);
        SetCardSelection(
            ExistingPolicyCard,
            ExistingPolicySelectedIcon,
            ExistingPolicySelectionText,
            _selectedSourceKind == PolicySourceKind.ExistingPolicy);
    }

    private void SetCardSelection(Border card, FontIcon icon, TextBlock label, bool selected)
    {
        card.BorderBrush = selected ? _selectedCardBorder : _defaultCardBorder;
        card.BorderThickness = selected ? new Thickness(2) : new Thickness(1);
        icon.Visibility = selected ? Visibility.Visible : Visibility.Collapsed;
        label.Visibility = selected ? Visibility.Visible : Visibility.Collapsed;
        label.Foreground = _selectedCardBorder;
    }

    private void PolicyNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (OutputPathTextBox is null || string.IsNullOrWhiteSpace(PolicyNameTextBox.Text))
        {
            return;
        }

        string baseName = PolicyOutputPlanner.SanitizeFileName(PolicyNameTextBox.Text);
        OutputPathTextBox.Text = PolicyOutputPlanner.GetAvailableOutputPath(
            GetAppControlDirectory(),
            baseName,
            _selectedSourceKind == PolicySourceKind.ExistingPolicy);
    }

    private void ApplySourceDefaults()
    {
        if (PolicyNameTextBox is null || OutputTemplateName is null || IdentityInfoBar is null)
        {
            return;
        }

        string baseName = PolicyOutputPlanner.CreateDefaultBaseName(
            _selectedSourceKind,
            _existingPolicy,
            DateOnly.FromDateTime(DateTime.Now));
        if (_selectedSourceKind == PolicySourceKind.ExistingPolicy && _existingPolicy is not null)
        {
            PolicyNameTextBox.Header = "Output file name";
            OutputTemplateName.Text = $"Existing policy: {Path.GetFileName(_existingPolicy.Path)}";
            IdentityInfoBar.Title = "Existing identity preserved";
            IdentityInfoBar.Message =
                $"The policy identity and unselected content will be preserved. Version {_existingPolicy.Version} will increment to {_existingPolicy.NextVersion}.";
        }
        else
        {
            PolicyNameTextBox.Header = "Policy name and file name";
            OutputTemplateName.Text = $"{GetSourceDisplayName(_selectedSourceKind)} template";
            IdentityInfoBar.Title = "New policy identity";
            IdentityInfoBar.Message =
                "The wizard assigns a unique policy ID, friendly name, and version 1.0.0.0 before compiling the .cip file.";
        }

        string outputPath = PolicyOutputPlanner.GetAvailableOutputPath(
            GetAppControlDirectory(),
            baseName,
            _selectedSourceKind == PolicySourceKind.ExistingPolicy);
        PolicyNameTextBox.Text = Path.GetFileNameWithoutExtension(outputPath);
        OutputPathTextBox.Text = outputPath;
    }

    private static string GetAppControlDirectory()
    {
        string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        return Path.Combine(documentsPath, "AppControl");
    }

    private static string GetSourceDisplayName(PolicySourceKind sourceKind)
    {
        return sourceKind switch
        {
            PolicySourceKind.SignedAndReputable => "Signed and reputable",
            PolicySourceKind.WindowsOnly => "Windows only",
            _ => "Existing policy"
        };
    }

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentStep > 1)
        {
            _currentStep--;
            NextButton.IsEnabled = true;
            UpdateStep();
        }
    }

    private async void NextButton_Click(object sender, RoutedEventArgs e)
    {
        ValidationInfoBar.IsOpen = false;

        if (_currentStep == 1)
        {
            if (_selectedSourceKind == PolicySourceKind.ExistingPolicy
                && _existingPolicy is null)
            {
                ValidationInfoBar.Severity = InfoBarSeverity.Warning;
                ValidationInfoBar.Title = "Choose an existing policy";
                ValidationInfoBar.Message = "Open an App Control XML policy before continuing.";
                ValidationInfoBar.IsOpen = true;
                return;
            }

            try
            {
                LoadPolicyConfiguration();
                _currentStep++;
                UpdateStep();
            }
            catch (InvalidDataException exception)
            {
                ShowSourceError("The policy behavior could not be loaded.", exception);
            }

            return;
        }

        if (_currentStep == 2)
        {
            if (!ApplyPolicyBehaviorChanges())
            {
                return;
            }

            _currentStep++;
            UpdateStep();
            return;
        }

        if (_currentStep == 3 && string.IsNullOrWhiteSpace(PolicyNameTextBox.Text))
        {
            ValidationInfoBar.Severity = InfoBarSeverity.Warning;
            ValidationInfoBar.Title = "Enter an output file name";
            ValidationInfoBar.Message = "The output file name cannot be empty.";
            ValidationInfoBar.IsOpen = true;
            PolicyNameTextBox.Focus(FocusState.Programmatic);
            return;
        }

        if (_currentStep < 4)
        {
            _currentStep++;
            UpdateStep();
            return;
        }

        await CreatePolicyAsync();
    }

    private async Task CreatePolicyAsync()
    {
        NextButton.IsEnabled = false;
        BackButton.IsEnabled = false;
        NextButton.Content = "Creating...";

        try
        {
            PolicyBuildResult buildResult = await _policyWorkflowService.BuildAsync(
                new PolicyBuildRequest(
                    _selectedSourceKind,
                    _existingPolicy?.Path,
                    PolicyNameTextBox.Text.Trim(),
                    OutputPathTextBox.Text,
                    _policyConfiguration));
            NextButton.Content = "Created";

            var content = new StackPanel { Spacing = 12 };
            content.Children.Add(new TextBlock
            {
                Text = _selectedSourceKind == PolicySourceKind.ExistingPolicy
                    ? $"The policy identity and unselected content were preserved. Version {_existingPolicy!.Version} was incremented to {buildResult.Version} before compilation."
                    : "The normalized template now has a unique identity, the selected policy behavior, and a compiled binary.",
                TextWrapping = TextWrapping.Wrap
            });
            content.Children.Add(new TextBox
            {
                Header = "XML policy",
                IsReadOnly = true,
                Text = buildResult.XmlPath
            });
            content.Children.Add(new TextBox
            {
                Header = "Compiled policy",
                IsReadOnly = true,
                Text = buildResult.BinaryPath
            });

            string identityText = string.IsNullOrWhiteSpace(buildResult.PolicyID)
                ? $"Legacy policy identity preserved    Version: {buildResult.Version ?? "Not specified"}"
                : $"Policy ID: {buildResult.PolicyID}    Version: {buildResult.Version ?? "Not specified"}";
            content.Children.Add(new TextBlock
            {
                Text = identityText,
                TextWrapping = TextWrapping.Wrap
            });

            var dialog = new ContentDialog
            {
                XamlRoot = Navigation.XamlRoot,
                Title = "Policy created",
                Content = content,
                PrimaryButtonText = "Create or edit another",
                CloseButtonText = "Done",
                DefaultButton = ContentDialogButton.Close
            };

            ContentDialogResult dialogResult = await dialog.ShowAsync();
            if (dialogResult == ContentDialogResult.Primary)
            {
                _currentStep = 1;
                _selectedSourceKind = PolicySourceKind.SignedAndReputable;
                _existingPolicy = null;
                ResetPolicyConfiguration();
                ExistingPolicyFileName.Visibility = Visibility.Collapsed;
                ApplySourceDefaults();
                UpdatePolicySourceCards();
                NextButton.IsEnabled = true;
                UpdateStep();
            }
            else
            {
                NextButton.Content = "Created";
                BackButton.IsEnabled = true;
            }
        }
        catch (UnauthorizedAccessException exception)
        {
            ShowCreationError("Windows denied access to the selected output location.", exception);
        }
        catch (InvalidDataException exception)
        {
            ShowCreationError("The policy source or output path is invalid.", exception);
        }
        catch (IOException exception)
        {
            ShowCreationError("The policy files could not be created.", exception);
        }
        catch (PolicyBuildException exception)
        {
            ShowCreationError("ConfigCI could not build the policy.", exception);
        }
    }

    private void ShowCreationError(string title, Exception exception)
    {
        ValidationInfoBar.Severity = InfoBarSeverity.Error;
        ValidationInfoBar.Title = title;
        ValidationInfoBar.Message = exception.Message;
        ValidationInfoBar.IsOpen = true;
        NextButton.Content = "Create policy";
        NextButton.IsEnabled = true;
        BackButton.IsEnabled = true;
    }

    private void UpdateStep()
    {
        TemplatePage.Visibility = _currentStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        BehaviorPage.Visibility = _currentStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = _currentStep == 3 ? Visibility.Visible : Visibility.Collapsed;
        ReviewPage.Visibility = _currentStep == 4 ? Visibility.Visible : Visibility.Collapsed;

        BackButton.IsEnabled = _currentStep > 1;
        NextButton.Content = _currentStep == 4 ? "Create policy" : "Next";
        ProgressText.Text = $"Step {_currentStep} of 4";
        WorkflowProgress.Value = _currentStep;

        TemplateStepNavigationItem.Content = $"{(_currentStep > 1 ? "✓" : "1")}  Choose source";
        BehaviorStepNavigationItem.Content = $"{(_currentStep > 2 ? "✓" : "2")}  Policy behavior";
        SettingsStepNavigationItem.Content = $"{(_currentStep > 3 ? "✓" : "3")}  Choose output";
        ReviewStepNavigationItem.Content = "4  Review";
        BehaviorStepNavigationItem.IsEnabled = _currentStep >= 2;
        SettingsStepNavigationItem.IsEnabled = _currentStep >= 3;
        ReviewStepNavigationItem.IsEnabled = _currentStep >= 4;

        if (_currentStep == 4)
        {
            PopulateReview();
        }
    }

    private void PopulateReview()
    {
        bool existingPolicy = _selectedSourceKind == PolicySourceKind.ExistingPolicy;
        bool legacyPolicy = existingPolicy && string.IsNullOrWhiteSpace(_existingPolicy?.PolicyID);

        ReviewPolicyName.Text = Path.GetFileName(OutputPathTextBox.Text);
        ReviewTemplate.Text = existingPolicy
            ? $"Existing policy: {Path.GetFileName(_existingPolicy!.Path)}"
            : $"{GetSourceDisplayName(_selectedSourceKind)} template";
        PolicyConfigurationSnapshot configuration = _policyConfiguration?.Snapshot
            ?? throw new InvalidOperationException("The policy configuration has not been loaded.");
        PolicyBehaviorSelection behavior = PolicyBehaviorSelection.FromSnapshot(configuration);
        string trustSources = string.Join(
            ", ",
            new[]
            {
                behavior.MicrosoftCloudReputation ? "Microsoft cloud reputation" : null,
                behavior.ManagedInstaller ? "Managed Installer" : null
            }.Where(value => value is not null));
        ReviewBehavior.Text =
            $"{(behavior.AuditMode ? "Audit" : "Enforced")} • "
            + $"{(behavior.UserModeCodeIntegrity ? "Applications and drivers" : "Drivers only")}"
            + (string.IsNullOrWhiteSpace(trustSources) ? string.Empty : $" • {trustSources}");
        ReviewChanges.Text = _policyChanges.Count == 0
            ? "No administrator policy-option changes. Unknown and unexposed content remains preserved."
            : string.Join(
                Environment.NewLine,
                _policyChanges.Select(change =>
                    $"{change.Name}: {change.Before} → {change.After}"));
        ReviewMode.Text = existingPolicy
            ? $"Identity preserved; version {_existingPolicy!.Version} → {_existingPolicy.NextVersion}; {_policyChanges.Count} behavior change(s)"
            : $"New unique identity; {_policyChanges.Count} behavior change(s)";
        ReviewFormat.Text = legacyPolicy ? "Legacy policy XML" : "Multiple-policy XML";
        ReviewUserMode.Text = legacyPolicy
            ? "XML and compiled .p7b"
            : "XML and compiled .cip";
        ReviewOutput.Text = OutputPathTextBox.Text;

        ReviewInfoBar.Title = existingPolicy ? "Ready to create edited policy" : "Ready to create policy";
        ReviewInfoBar.Message = existingPolicy
            ? $"ConfigCI will preserve the selected policy's identity and unselected content, increment version {_existingPolicy!.Version} to {_existingPolicy.NextVersion}, apply the reviewed behavior changes, and compile it."
            : "ConfigCI will assign a unique identity, apply the reviewed behavior choices to the normalized template, and compile the policy.";
    }

    private void LoadPolicyConfiguration()
    {
        _policyConfiguration = _policyWorkflowService.OpenPolicyConfiguration(
            _selectedSourceKind,
            _existingPolicy?.Path);
        _initialPolicyConfiguration = _policyConfiguration.Snapshot;
        _initialPolicyDocument = _policyConfiguration.ToDocument();
        _policyChanges = [];
        BehaviorSourceTitle.Text = _selectedSourceKind == PolicySourceKind.ExistingPolicy
            ? $"Loaded from {Path.GetFileName(_existingPolicy!.Path)}"
            : $"Loaded from {GetSourceDisplayName(_selectedSourceKind)} template";
        BehaviorSourceMessage.Text = _selectedSourceKind == PolicySourceKind.ExistingPolicy
            ? "The controls below reflect the selected policy. Unknown and unexposed content remains preserved."
            : "The controls below reflect the normalized Microsoft template defaults. Reserved settings removed by normalization aren't shown as administrator changes.";
        PopulatePolicyBehavior(_policyConfiguration.Snapshot);
    }

    private void PopulatePolicyBehavior(PolicyConfigurationSnapshot snapshot)
    {
        PolicyBehaviorSelection selection = PolicyBehaviorSelection.FromSnapshot(snapshot);
        _updatingPolicyControls = true;
        try
        {
            SetDeploymentMode(selection.AuditMode);
            SetPolicyScope(selection.UserModeCodeIntegrity);
            CloudReputationToggle.IsOn = selection.MicrosoftCloudReputation;
            ManagedInstallerToggle.IsOn = selection.ManagedInstaller;
            AllowSupplementalToggle.IsOn = selection.AllowSupplementalPolicies;
            ScriptEnforcementToggle.IsOn = selection.ScriptEnforcement;
            DynamicCodeSecurityToggle.IsOn = selection.DynamicCodeSecurity;
            HvciToggle.IsOn = snapshot.HvciOptions > 0;
            WhqlOnlyToggle.IsOn = selection.WhqlOnlyDrivers;
            FlightSigningToggle.IsOn = selection.FlightSigning;
            AdvancedBootToggle.IsOn = selection.AdvancedBootOptionsMenu;
            BootAuditToggle.IsOn = selection.BootAuditOnFailure;
            InvalidateEasToggle.IsOn = selection.InvalidateEAsOnReboot;
            UpdateNoRebootToggle.IsOn = selection.UpdatePolicyWithoutReboot;
            StoreAppsToggle.IsOn = selection.EnforceStoreApplications;
            FilePathProtectionToggle.IsOn = selection.RuntimeFilePathRuleProtection;
            RevokedAsUnsignedToggle.IsOn = selection.RevokedExpiredAsUnsigned;
        }
        finally
        {
            _updatingPolicyControls = false;
        }

        bool isSupplemental = snapshot.PolicyType == AppControlPolicyType.Supplemental;
        bool isAppIdTagging = snapshot.PolicyType == AppControlPolicyType.AppIdTagging;
        PolicyTypeInfoBar.Title = snapshot.PolicyType switch
        {
            AppControlPolicyType.Supplemental => "Supplemental policy",
            AppControlPolicyType.AppIdTagging => "AppId tagging policy",
            AppControlPolicyType.Unknown => "Policy type not declared",
            _ => "Base policy"
        };
        PolicyTypeInfoBar.Message = snapshot.PolicyType switch
        {
            AppControlPolicyType.Supplemental =>
                "Only options valid for supplemental policies are editable. Base-policy behavior is inherited.",
            AppControlPolicyType.AppIdTagging =>
                "This specialized policy type has restricted option editing.",
            AppControlPolicyType.Unknown =>
                "The policy doesn't declare a type. Existing content will be preserved and base-policy controls are shown cautiously.",
            _ => "This policy can define application, driver, trust, and supplemental-policy behavior."
        };

        bool standardPolicy = !isSupplemental && !isAppIdTagging;
        AuditModeButton.IsEnabled = standardPolicy;
        EnforcedModeButton.IsEnabled = standardPolicy;
        ApplicationsAndDriversButton.IsEnabled = standardPolicy;
        DriversOnlyButton.IsEnabled = standardPolicy;
        AllowSupplementalToggle.IsEnabled = snapshot.PolicyType is AppControlPolicyType.Base
            or AppControlPolicyType.Unknown;
        HvciToggle.IsEnabled = standardPolicy;
        WhqlOnlyToggle.IsEnabled = standardPolicy;
        FlightSigningToggle.IsEnabled = standardPolicy;
        AdvancedBootToggle.IsEnabled = standardPolicy;
        BootAuditToggle.IsEnabled = standardPolicy;
        UpdateNoRebootToggle.IsEnabled = standardPolicy;
        StoreAppsToggle.IsEnabled = standardPolicy;
        RevokedAsUnsignedToggle.IsEnabled = standardPolicy;
        DynamicCodeSecurityToggle.IsEnabled = standardPolicy;
        ScriptEnforcementToggle.IsEnabled = standardPolicy;
        ManagedInstallerToggle.IsEnabled = !isAppIdTagging;
        CloudReputationToggle.IsEnabled = !isAppIdTagging;
        FilePathProtectionToggle.IsEnabled = !isAppIdTagging;
        UpdateUserModeControlAvailability();

        HvciSummaryText.Text = snapshot.RawHvciOptions is null
            ? "Not specified in the source. It remains disabled unless you change it."
            : $"Source schema value {snapshot.RawHvciOptions}. Any explicit change is written as 0 or 1.";
        bool unsignedAllowed =
            snapshot.GetOption(PolicyOptionId.UnsignedPolicyAllowed).IsEnabled;
        SigningStatusText.Text = unsignedAllowed
            ? "Unsigned policy output is allowed. Signing is handled in a future Deployment protection stage."
            : "This policy requires signing. A deployable binary can't be created until the Deployment protection stage is implemented.";

        int platformSettingCount = snapshot.Settings.Count(setting =>
            !string.Equals(setting.Key.Provider, "PolicyInfo", StringComparison.Ordinal));
        PlatformSettingsSummary.Text = platformSettingCount == 0
            ? "No configurable platform behaviors were detected. PolicyInfo metadata is preserved."
            : $"{platformSettingCount} secure or app setting(s) detected and preserved. Curated controls will appear only for validated catalog entries.";

        var compatibilityMessages = snapshot.CompatibilityFindings
            .Select(finding => finding.Message)
            .Concat(snapshot.UnknownOptions.Select(option =>
                $"Unknown option preserved: {option.XmlValue}"))
            .ToArray();
        CompatibilitySummary.Text = compatibilityMessages.Length == 0
            ? "No unsupported, reserved, or unknown policy options were detected."
            : string.Join(Environment.NewLine, compatibilityMessages);
        DynamicCodeWarning.IsOpen = DynamicCodeSecurityToggle.IsOn;
        UpdateBehaviorChangePreview();
    }

    private bool ApplyPolicyBehaviorChanges()
    {
        if (_policyConfiguration is null || _initialPolicyConfiguration is null)
        {
            ValidationInfoBar.Severity = InfoBarSeverity.Error;
            ValidationInfoBar.Title = "Policy behavior is unavailable";
            ValidationInfoBar.Message = "Return to source selection and reload the policy.";
            ValidationInfoBar.IsOpen = true;
            return false;
        }

        if (!_policyConfiguration.Snapshot
            .GetOption(PolicyOptionId.UnsignedPolicyAllowed)
            .IsEnabled)
        {
            ValidationInfoBar.Severity = InfoBarSeverity.Warning;
            ValidationInfoBar.Title = "Signed-policy output isn't available yet";
            ValidationInfoBar.Message =
                "This policy requires a signed binary. The Deployment protection stage must be implemented before this edit can produce deployable output.";
            ValidationInfoBar.IsOpen = true;
            return false;
        }

        PolicyConfigurationDelta delta = CreatePolicyBehaviorDelta();
        _policyConfiguration = PolicyConfigurationEditor.FromDocument(
            _initialPolicyDocument
            ?? throw new InvalidOperationException("The source policy document is unavailable."));
        _policyConfiguration.Apply(delta);
        _policyChanges = PolicyConfigurationComparer.Compare(
            _initialPolicyConfiguration,
            _policyConfiguration.Snapshot);
        return true;
    }

    private PolicyConfigurationDelta CreatePolicyBehaviorDelta()
    {
        var selection = new PolicyBehaviorSelection(
            AuditModeButton.IsChecked == true,
            ApplicationsAndDriversButton.IsChecked == true,
            CloudReputationToggle.IsOn,
            ManagedInstallerToggle.IsOn,
            AllowSupplementalToggle.IsOn,
            ScriptEnforcementToggle.IsOn,
            DynamicCodeSecurityToggle.IsOn,
            WhqlOnlyToggle.IsOn,
            FlightSigningToggle.IsOn,
            AdvancedBootToggle.IsOn,
            BootAuditToggle.IsOn,
            InvalidateEasToggle.IsOn,
            UpdateNoRebootToggle.IsOn,
            StoreAppsToggle.IsOn,
            FilePathProtectionToggle.IsOn,
            RevokedAsUnsignedToggle.IsOn);
        PolicyConfigurationDelta optionDelta = selection.ToDelta();
        bool initialHvciEnabled =
            (_initialPolicyConfiguration?.HvciOptions ?? 0) > 0;
        PolicyHvciChange? hvciChange = HvciToggle.IsOn == initialHvciEnabled
            ? null
            : new PolicyHvciChange(HvciToggle.IsOn ? 1u : 0u);
        return new PolicyConfigurationDelta
        {
            OptionChanges = optionDelta.OptionChanges,
            HvciChange = hvciChange
        };
    }

    private void DeploymentModeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updatingPolicyControls)
        {
            return;
        }

        SetDeploymentMode(ReferenceEquals(sender, AuditModeButton));
        UpdateBehaviorChangePreview();
    }

    private void PolicyScopeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updatingPolicyControls)
        {
            return;
        }

        SetPolicyScope(ReferenceEquals(sender, ApplicationsAndDriversButton));
        if (DriversOnlyButton.IsChecked == true)
        {
            ClearUserModeOnlySelections();
        }

        UpdateUserModeControlAvailability();
        UpdateBehaviorChangePreview();
    }

    private void DynamicCodeSecurityToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (DynamicCodeWarning is not null)
        {
            DynamicCodeWarning.IsOpen = DynamicCodeSecurityToggle.IsOn;
        }
    }

    private void CloudReputationToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_updatingPolicyControls)
        {
            return;
        }

        if (!CloudReputationToggle.IsOn)
        {
            InvalidateEasToggle.IsOn = false;
        }

        UpdateUserModeControlAvailability();
        UpdateBehaviorChangePreview();
    }

    private void SetDeploymentMode(bool auditMode)
    {
        AuditModeButton.IsChecked = auditMode;
        EnforcedModeButton.IsChecked = !auditMode;
    }

    private void SetPolicyScope(bool applicationsAndDrivers)
    {
        ApplicationsAndDriversButton.IsChecked = applicationsAndDrivers;
        DriversOnlyButton.IsChecked = !applicationsAndDrivers;
    }

    private void UpdateUserModeControlAvailability()
    {
        bool inheritedUserMode =
            _policyConfiguration?.Snapshot.PolicyType == AppControlPolicyType.Supplemental;
        bool userMode = ApplicationsAndDriversButton.IsChecked == true || inheritedUserMode;
        bool appIdTagging =
            _policyConfiguration?.Snapshot.PolicyType == AppControlPolicyType.AppIdTagging;
        CloudReputationToggle.IsEnabled = userMode && !appIdTagging;
        ManagedInstallerToggle.IsEnabled = userMode && !appIdTagging;
        InvalidateEasToggle.IsEnabled = userMode
            && CloudReputationToggle.IsOn
            && _policyConfiguration?.Snapshot.PolicyType is not AppControlPolicyType.Supplemental
            and not AppControlPolicyType.AppIdTagging;
        ScriptEnforcementToggle.IsEnabled = userMode
            && _policyConfiguration?.Snapshot.PolicyType is not AppControlPolicyType.Supplemental
            and not AppControlPolicyType.AppIdTagging;
        DynamicCodeSecurityToggle.IsEnabled = ScriptEnforcementToggle.IsEnabled;
        StoreAppsToggle.IsEnabled = ScriptEnforcementToggle.IsEnabled;
        RevokedAsUnsignedToggle.IsEnabled = ScriptEnforcementToggle.IsEnabled;
    }

    private void ClearUserModeOnlySelections()
    {
        CloudReputationToggle.IsOn = false;
        InvalidateEasToggle.IsOn = false;
        ManagedInstallerToggle.IsOn = false;
        DynamicCodeSecurityToggle.IsOn = false;
        StoreAppsToggle.IsOn = false;
        RevokedAsUnsignedToggle.IsOn = false;
    }

    private void RegisterPolicyControlChangeHandlers()
    {
        ToggleSwitch[] controls =
        [
            AllowSupplementalToggle,
            CloudReputationToggle,
            InvalidateEasToggle,
            ManagedInstallerToggle,
            ScriptEnforcementToggle,
            DynamicCodeSecurityToggle,
            HvciToggle,
            WhqlOnlyToggle,
            FlightSigningToggle,
            AdvancedBootToggle,
            BootAuditToggle,
            UpdateNoRebootToggle,
            StoreAppsToggle,
            FilePathProtectionToggle,
            RevokedAsUnsignedToggle
        ];
        foreach (ToggleSwitch control in controls)
        {
            control.Toggled += PolicyOptionControl_Toggled;
        }
    }

    private void PolicyOptionControl_Toggled(object sender, RoutedEventArgs e)
    {
        if (!_updatingPolicyControls)
        {
            UpdateBehaviorChangePreview();
        }
    }

    private void UpdateBehaviorChangePreview()
    {
        if (_initialPolicyConfiguration is null || _initialPolicyDocument is null)
        {
            return;
        }

        PolicyConfigurationEditor preview =
            PolicyConfigurationEditor.FromDocument(_initialPolicyDocument);
        preview.Apply(CreatePolicyBehaviorDelta());
        _policyChanges = PolicyConfigurationComparer.Compare(
            _initialPolicyConfiguration,
            preview.Snapshot);

        ResetBehaviorButton.IsEnabled = _policyChanges.Count > 0;
        BehaviorChangeTitle.Text = _policyChanges.Count == 0
            ? "No changes from source"
            : $"{_policyChanges.Count} administrator change(s)";
        BehaviorChangeDetails.Text = _policyChanges.Count == 0
            ? "All exposed settings still match the selected policy source."
            : string.Join(
                Environment.NewLine,
                _policyChanges
                    .Take(4)
                    .Select(change =>
                        $"{change.Name}: {change.Before} → {change.After}"))
                + (_policyChanges.Count > 4
                    ? $"{Environment.NewLine}+ {_policyChanges.Count - 4} more"
                    : string.Empty);
    }

    private void ResetBehaviorButton_Click(object sender, RoutedEventArgs e)
    {
        if (_initialPolicyDocument is null)
        {
            return;
        }

        _policyConfiguration =
            PolicyConfigurationEditor.FromDocument(_initialPolicyDocument);
        _policyChanges = [];
        PopulatePolicyBehavior(_initialPolicyConfiguration!);
    }

    private void ResetPolicyConfiguration()
    {
        _policyConfiguration = null;
        _initialPolicyConfiguration = null;
        _initialPolicyDocument = null;
        _policyChanges = [];
    }
}
