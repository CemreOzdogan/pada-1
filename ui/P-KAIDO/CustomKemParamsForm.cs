using System.Text.Json;

namespace PKaido;

internal sealed record CustomKemParamsResult(uint K, long N, long Q);

/// Modal parameter-entry dialog for the "custom" ML-KEM engine. Mirrors
/// `CustomDsaParamsForm` structurally. The derived-knobs preview (eta1/eta2/du/dv) is never
/// computed here in C# — it's populated only from pqc-cli's `validate-custom` response, so the
/// preview can never disagree with what `keygen-custom` actually does with the same inputs.
internal sealed class CustomKemParamsForm : Form
{
    private readonly NumericUpDown _kBox;
    private readonly NumericUpDown _nBox;
    private readonly NumericUpDown _qBox;
    private readonly Label _qCheckLabel;
    private readonly Label _previewLabel;
    private readonly Label _errorLabel;
    private readonly Button _okButton;

    private readonly string _cliPath;

    public CustomKemParamsResult? Result { get; private set; }

    private CustomKemParamsForm(string cliPath)
    {
        _cliPath = cliPath;

        Text = "Custom ML-KEM parameters";
        Width = 480;
        Height = 400;
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

        _kBox = AddNumericRow(root, "k (dimension of square matrix A)", 1, 8, 3);
        _nBox = AddNumericRow(root, "n (ring degree, must be a power of two)", 32, 1024, 256);
        _qBox = AddNumericRow(root, "q (NTT-suitable prime)", 5, 1_999_999_999, 7_681);

        // Standalone quick check: is this (q, n) pair prime/power-of-two and NTT-suitable,
        // independent of k — lets you try candidate primes before committing to a full set.
        var checkQButton = new Button { Text = "Check q", AutoSize = true, Anchor = AnchorStyles.Left };
        checkQButton.Click += (_, _) => CheckQ();
        _qCheckLabel = new Label { Text = string.Empty, AutoSize = true, MaximumSize = new Size(300, 0), Anchor = AnchorStyles.Left };
        int checkQRow = root.RowCount;
        root.RowCount++;
        root.Controls.Add(checkQButton, 0, checkQRow);
        root.Controls.Add(_qCheckLabel, 1, checkQRow);

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
            Text = "eta1: -   eta2: -   du: -   dv: -",
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
        foreach (var box in new[] { _kBox, _nBox, _qBox })
        {
            box.ValueChanged += (_, _) => InvalidatePreview();
        }
        _qBox.ValueChanged += (_, _) => _qCheckLabel.Text = string.Empty;
        _nBox.ValueChanged += (_, _) => _qCheckLabel.Text = string.Empty;
    }

    public static CustomKemParamsResult? ShowParamsDialog(IWin32Window owner, string cliPath)
    {
        using var form = new CustomKemParamsForm(cliPath);
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

    private void InvalidatePreview()
    {
        _previewLabel.Text = "eta1: -   eta2: -   du: -   dv: -";
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
            "ml-kem", "validate-custom",
            "--k", _kBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--n", _nBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--q", _qBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

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
                _previewLabel.Text = "eta1: -   eta2: -   du: -   dv: -";
                _okButton.Enabled = false;
                return;
            }

            long eta1 = root.GetProperty("eta1").GetInt64();
            long eta2 = root.GetProperty("eta2").GetInt64();
            long du = root.GetProperty("du").GetInt64();
            long dv = root.GetProperty("dv").GetInt64();

            _previewLabel.Text = $"eta1: {eta1}   eta2: {eta2}   du: {du}   dv: {dv}";
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
            "ml-kem", "check-q",
            "--q", _qBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--n", _nBox.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
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
                _qCheckLabel.Text = "NTT-suitable (prime, q ≡ 1 mod 2n)";
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

    private CustomKemParamsResult BuildResult() => new(
        (uint)_kBox.Value,
        (long)_nBox.Value,
        (long)_qBox.Value);
}
