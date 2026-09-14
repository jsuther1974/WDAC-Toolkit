using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using Windows.Graphics;
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
                $"The policy identity, rules, and options remain unchanged. Version {_existingPolicy.Version} will increment to {_existingPolicy.NextVersion}.";
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

        if (_currentStep == 1
            && _selectedSourceKind == PolicySourceKind.ExistingPolicy
            && _existingPolicy is null)
        {
            ValidationInfoBar.Severity = InfoBarSeverity.Warning;
            ValidationInfoBar.Title = "Choose an existing policy";
            ValidationInfoBar.Message = "Open an App Control XML policy before continuing.";
            ValidationInfoBar.IsOpen = true;
            return;
        }

        if (_currentStep == 2 && string.IsNullOrWhiteSpace(PolicyNameTextBox.Text))
        {
            ValidationInfoBar.Severity = InfoBarSeverity.Warning;
            ValidationInfoBar.Title = "Enter an output file name";
            ValidationInfoBar.Message = "The output file name cannot be empty.";
            ValidationInfoBar.IsOpen = true;
            PolicyNameTextBox.Focus(FocusState.Programmatic);
            return;
        }

        if (_currentStep < 3)
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
                    OutputPathTextBox.Text));
            NextButton.Content = "Created";

            var content = new StackPanel { Spacing = 12 };
            content.Children.Add(new TextBlock
            {
                Text = _selectedSourceKind == PolicySourceKind.ExistingPolicy
                    ? $"The policy identity, rules, and options were preserved. Version {_existingPolicy!.Version} was incremented to {buildResult.Version} before compilation."
                    : "The template now has a unique identity and a compiled binary. Template rules and options were not changed.",
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
        SettingsPage.Visibility = _currentStep == 2 ? Visibility.Visible : Visibility.Collapsed;
        ReviewPage.Visibility = _currentStep == 3 ? Visibility.Visible : Visibility.Collapsed;

        BackButton.IsEnabled = _currentStep > 1;
        NextButton.Content = _currentStep == 3 ? "Create policy" : "Next";
        ProgressText.Text = $"Step {_currentStep} of 3";
        WorkflowProgress.Value = _currentStep;

        TemplateStepNavigationItem.Content = $"{(_currentStep > 1 ? "✓" : "1")}  Choose source";
        SettingsStepNavigationItem.Content = $"{(_currentStep > 2 ? "✓" : "2")}  Choose output";
        ReviewStepNavigationItem.Content = "3  Review";
        SettingsStepNavigationItem.IsEnabled = _currentStep >= 2;
        ReviewStepNavigationItem.IsEnabled = _currentStep >= 3;

        if (_currentStep == 3)
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
        ReviewMode.Text = existingPolicy
            ? $"Identity and rules unchanged; version {_existingPolicy!.Version} → {_existingPolicy.NextVersion}"
            : "New unique identity; rules unchanged";
        ReviewFormat.Text = legacyPolicy ? "Legacy policy XML" : "Multiple-policy XML";
        ReviewUserMode.Text = legacyPolicy
            ? "XML and compiled .p7b"
            : "XML and compiled .cip";
        ReviewOutput.Text = OutputPathTextBox.Text;

        ReviewInfoBar.Title = existingPolicy ? "Ready to create edited policy" : "Ready to create policy";
        ReviewInfoBar.Message = existingPolicy
            ? $"ConfigCI will preserve the selected policy's identity, rules, and options, increment version {_existingPolicy!.Version} to {_existingPolicy.NextVersion}, and compile it."
            : "ConfigCI will assign a unique identity and compile the policy. The template's rules and options remain unchanged.";
    }
}
