using System.Text.Json;

namespace PKaido;

internal sealed record CustomDsaParamsResult(
    uint K, uint L, long Q, long Gamma1,
    uint? Eta, long? Gamma2, uint? Tau, uint? Omega, uint? Lambda);

/// Modal parameter-entry dialog for the "custom" ML-DSA engine. The derived-knobs preview
/// (eta/gamma2/tau/omega) is never computed here in C# — it's populated only from pqc-cli's
/// `validate-custom` response, so the preview can never disagree with what `keygen-custom`
/// actually does with the same inputs.
internal sealed class CustomDsaParamsForm : Form
{
    private readonly NumericUpDown _kBox;
    private readonly NumericUpDown _lBox;
    private readonly NumericUpDown _qBox;
    private readonly NumericUpDown _gamma1Box;
    private readonly TextBox _etaBox;
    private readonly TextBox _gamma2Box;
    private readonly TextBox _tauBox;
    private readonly TextBox _omegaBox;
    private readonly TextBox _lambdaBox;
    private readonly Label _qCheckLabel;
    private readonly Label _previewLabel;
    private readonly Label _errorLabel;
    private readonly Button _okButton;

    private readonly string _cliPath;

    public CustomDsaParamsResult? Result { get; private set; }

    private CustomDsaParamsForm(string cliPath)
    {
        _cliPath = cliPath;

        Text = "Custom ML-DSA parameters";
        Width = 480;
        Height = 560;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            AutoSize = true,
            Padding = new Padding(12),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Controls.Add(root);

        _kBox = AddNumericRow(root, "k (matrix rows)", 1, 8, 4);
        _lBox = AddNumericRow(root, "l (matrix columns)", 1, 8, 4);
        _qBox = AddNumericRow(root, "q (NTT-suitable prime)", 5, 1_999_999_999, 8_380_417);

        // Standalone quick check: is this q prime and NTT-suitable, independent of k/l/gamma1 —
        // lets you try candidate primes before committing to a full parameter set.
        var checkQButton = new Button { Text = "Check q", AutoSize = true, Anchor = AnchorStyles.Left };
        checkQButton.Click += (_, _) => CheckQ();
        _qCheckLabel = new Label { Text = string.Empty, AutoSize = true, MaximumSize = new Size(300, 0), Anchor = AnchorStyles.Left };
        int checkQRow = root.RowCount;
        root.RowCount++;
        root.Controls.Add(checkQButton, 0, checkQRow);
        root.Controls.Add(_qCheckLabel, 1, checkQRow);

        _gamma1Box = AddNumericRow(root, "gamma1 (coefficient bound)", 1, 2_000_000_000, 131_072);

        var overridesCaption = new Label
        {
            Text = "Optional overrides (blank = calibrated heuristic default):",
            AutoSize = true,
            Padding = new Padding(0, 10, 0, 2),
        };
        int overridesRow = root.RowCount;
        root.RowCount++;
        root.Controls.Add(overridesCaption, 0, overridesRow);
        root.SetColumnSpan(overridesCaption, 2);

        _etaBox = AddOptionalTextRow(root, "eta override");
        _gamma2Box = AddOptionalTextRow(root, "gamma2 override");
        _tauBox = AddOptionalTextRow(root, "tau override");
        _omegaBox = AddOptionalTextRow(root, "omega override");
        _lambdaBox = AddOptionalTextRow(root, "lambda override (c̃ byte length)");

        var previewCaption = new Label
        {
            Text = "Derived (auto-computed on Validate):",
            AutoSize = true,
            Padding = new Padding(0, 12, 0, 2),
        };
        int row = root.RowCount;
        root.RowCount++;
        root.Controls.Add(previewCaption, 0, row);
        root.SetColumnSpan(previewCaption, 2);

        _previewLabel = new Label
        {
            Text = "eta: -   gamma2: -   tau: -   omega: -",
            AutoSize = true,
            Font = new Font(FontFamily.GenericMonospace, 9),
        };
        row = root.RowCount;
        root.RowCount++;
        root.Controls.Add(_previewLabel, 0, row);
        root.SetColumnSpan(_previewLabel, 2);

        _errorLabel = new Label
        {
            Text = string.Empty,
            AutoSize = true,
            MaximumSize = new Size(430, 0),
            ForeColor = MainForm.ErrorColor,
            Padding = new Padding(0, 8, 0, 0),
        };
        row = root.RowCount;
        root.RowCount++;
        root.Controls.Add(_errorLabel, 0, row);
        root.SetColumnSpan(_errorLabel, 2);

        var validateButton = new Button { Text = "Validate", Width = 90, AutoSize = true };
        validateButton.Click += (_, _) => ValidateParams();
        row = root.RowCount;
        root.RowCount++;
        root.Controls.Add(validateButton, 0, row);

        var buttonRow = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        var cancelButton = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        _okButton = new Button { Text = "OK", Width = 90, DialogResult = DialogResult.OK, Enabled = false };
        _okButton.Click += (_, _) => Result = BuildResult();
        buttonRow.Controls.Add(cancelButton);
        buttonRow.Controls.Add(_okButton);
        root.Controls.Add(buttonRow, 1, row);

        AcceptButton = _okButton;
        CancelButton = cancelButton;

        BackColor = MainForm.BgColor;
        ForeColor = MainForm.TextColor;
        MainForm.ThemeTree(this);

        // Any field change invalidates the last validation — force re-validate before OK is usable.
        foreach (var box in new[] { _kBox, _lBox, _qBox, _gamma1Box })
        {
            box.ValueChanged += (_, _) => InvalidatePreview();
        }
        foreach (var box in new[] { _etaBox, _gamma2Box, _tauBox, _omegaBox, _lambdaBox })
        {
            box.TextChanged += (_, _) => InvalidatePreview();
        }
        _qBox.ValueChanged += (_, _) => _qCheckLabel.Text = string.Empty;
    }

    public static CustomDsaParamsResult? ShowParamsDialog(IWin32Window owner, string cliPath)
    {
        using var form = new CustomDsaParamsForm(cliPath);
        return form.ShowDialog(owner) == DialogResult.OK ? form.Result : null;
    }

    private NumericUpDown AddNumericRow(TableLayoutPanel root, string label, decimal min, decimal max, decimal value)
    {
        int row = root.RowCount;
        root.RowCount++;

        var lbl = new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 10, 0) };
        root.Controls.Add(lbl, 0, row);

        var box = new NumericUpDown
        {
            Minimum = min,
            Maximum = max,
            Value = value,
            Width = 200,
            Anchor = AnchorStyles.Left,
        };
        root.Controls.Add(box, 1, row);
        return box;
    }

    private TextBox AddOptionalTextRow(TableLayoutPanel root, string label)
    {
        int row = root.RowCount;
        root.RowCount++;

        var lbl = new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 10, 0) };
        root.Controls.Add(lbl, 0, row);

        var box = new TextBox { Dock = DockStyle.Fill };
        root.Controls.Add(box, 1, row);
        return box;
    }

    private void InvalidatePreview()
    {
        _previewLabel.Text = "eta: -   gamma2: -   tau: -   omega: -";
        _okButton.Enabled = false;
        _errorLabel.Text = string.Empty;
    }

    private void ValidateParams()
    {
        if (string.IsNullOrWhiteSpace(_cliPath))
        {
            _errorLabel.Text = "Set the path to pqc-cli.exe first (in the main window).";
            return;
        }

        var args = new List<string>
        {
            "ml-dsa", "validate-custom",
            "--k", _kBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--l", _lBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--q", _qBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--gamma1", _gamma1Box.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        foreach (var (flag, box) in new[] { ("--eta", _etaBox), ("--gamma2", _gamma2Box), ("--tau", _tauBox), ("--omega", _omegaBox), ("--lambda", _lambdaBox) })
        {
            if (!string.IsNullOrWhiteSpace(box.Text))
            {
                if (!long.TryParse(box.Text.Trim(), out _))
                {
                    _errorLabel.Text = $"'{flag}' override must be a whole number (or blank).";
                    return;
                }
                args.Add(flag);
                args.Add(box.Text.Trim());
            }
        }

        CliResult result;
        try
        {
            result = CliRunner.Run(_cliPath, args);
        }
        catch (Exception ex)
        {
            _errorLabel.Text = $"Failed to launch pqc-cli: {ex.Message}";
            _okButton.Enabled = false;
            return;
        }

        string rawJson = result.StdOut.Length > 0 ? result.StdOut : result.StdErr;
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            bool ok = root.TryGetProperty("ok", out var okProp) && okProp.GetBoolean();
            if (!ok)
            {
                _errorLabel.Text = root.TryGetProperty("error", out var err) ? err.GetString() ?? "error" : "error";
                _previewLabel.Text = "eta: -   gamma2: -   tau: -   omega: -";
                _okButton.Enabled = false;
                return;
            }

            long eta = root.GetProperty("eta").GetInt64();
            long gamma2 = root.GetProperty("gamma2").GetInt64();
            long tau = root.GetProperty("tau").GetInt64();
            long omega = root.GetProperty("omega").GetInt64();

            _previewLabel.Text = $"eta: {eta}   gamma2: {gamma2}   tau: {tau}   omega: {omega}";
            _errorLabel.Text = string.Empty;
            _okButton.Enabled = true;
        }
        catch (JsonException)
        {
            _errorLabel.Text = string.IsNullOrEmpty(rawJson) ? "(no output from pqc-cli)" : rawJson;
            _okButton.Enabled = false;
        }
    }

    private void CheckQ()
    {
        if (string.IsNullOrWhiteSpace(_cliPath))
        {
            _qCheckLabel.ForeColor = MainForm.ErrorColor;
            _qCheckLabel.Text = "Set the path to pqc-cli.exe first (in the main window).";
            return;
        }

        var args = new List<string>
        {
            "ml-dsa", "check-q",
            "--q", _qBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        CliResult result;
        try
        {
            result = CliRunner.Run(_cliPath, args);
        }
        catch (Exception ex)
        {
            _qCheckLabel.ForeColor = MainForm.ErrorColor;
            _qCheckLabel.Text = $"Failed to launch pqc-cli: {ex.Message}";
            return;
        }

        string rawJson = result.StdOut.Length > 0 ? result.StdOut : result.StdErr;
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            bool ok = root.TryGetProperty("ok", out var okProp) && okProp.GetBoolean();
            if (ok)
            {
                _qCheckLabel.ForeColor = MainForm.GoldColor;
                _qCheckLabel.Text = "NTT-suitable (prime, q ≡ 1 mod 512)";
            }
            else
            {
                _qCheckLabel.ForeColor = MainForm.ErrorColor;
                _qCheckLabel.Text = root.TryGetProperty("error", out var err) ? err.GetString() ?? "error" : "error";
            }
        }
        catch (JsonException)
        {
            _qCheckLabel.ForeColor = MainForm.ErrorColor;
            _qCheckLabel.Text = string.IsNullOrEmpty(rawJson) ? "(no output from pqc-cli)" : rawJson;
        }
    }

    private static uint? ParseOptionalUInt(TextBox box) =>
        string.IsNullOrWhiteSpace(box.Text) ? null : uint.Parse(box.Text.Trim());

    private static long? ParseOptionalLong(TextBox box) =>
        string.IsNullOrWhiteSpace(box.Text) ? null : long.Parse(box.Text.Trim());

    private CustomDsaParamsResult BuildResult() => new(
        (uint)_kBox.Value,
        (uint)_lBox.Value,
        (long)_qBox.Value,
        (long)_gamma1Box.Value,
        ParseOptionalUInt(_etaBox),
        ParseOptionalLong(_gamma2Box),
        ParseOptionalUInt(_tauBox),
        ParseOptionalUInt(_omegaBox),
        ParseOptionalUInt(_lambdaBox));
}
