using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace PKaido;

internal sealed class MainForm : Form
{
    // Kaido-inspired palette: near-black indigo, azure dragon-scale blue, gold horns/eyes as the warm accent.
    // Internal (not just the ones CustomDsaParamsForm needs) so any future dialog can match exactly.
    internal static readonly Color BgColor = ColorTranslator.FromHtml("#14141C");
    internal static readonly Color PanelColor = ColorTranslator.FromHtml("#1F2233");
    internal static readonly Color InputBgColor = ColorTranslator.FromHtml("#161A24");
    internal static readonly Color BorderColor = ColorTranslator.FromHtml("#3A4160");
    internal static readonly Color TextColor = ColorTranslator.FromHtml("#E8E6DE");
    internal static readonly Color SecondaryTextColor = ColorTranslator.FromHtml("#8891A8");
    internal static readonly Color AccentColor = ColorTranslator.FromHtml("#2E7FD9");
    internal static readonly Color AccentHoverColor = ColorTranslator.FromHtml("#4FA3F5");
    internal static readonly Color GoldColor = ColorTranslator.FromHtml("#D4A94E");
    internal static readonly Color ErrorColor = ColorTranslator.FromHtml("#C23B3B");

    private enum FieldKind { InputFile, OutputFile, OutputFolder, TextMessage }

    private sealed record FieldSpec(string ArgName, string Label, FieldKind Kind, bool Required);

    private static readonly Dictionary<string, string[]> VariantsByScheme = new()
    {
        ["ML-DSA"] = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
        ["ML-KEM"] = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"],
    };

    private static readonly Dictionary<string, string[]> EnginesByScheme = new()
    {
        ["ML-DSA"] = ["rustcrypto", "libcrux", "custom"],
        ["ML-KEM"] = ["rustcrypto", "libcrux"],
    };

    private static readonly Dictionary<string, string[]> OperationsByScheme = new()
    {
        ["ML-DSA"] = ["Keygen", "Sign", "Verify"],
        ["ML-KEM"] = ["Keygen", "Encapsulate", "Decapsulate"],
    };

    private static readonly Dictionary<(string Scheme, string Op), FieldSpec[]> FieldsByOp = new()
    {
        [("ML-DSA", "Keygen")] =
        [
            new FieldSpec("out-dir", "Output folder (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFolder, Required: false),
        ],
        [("ML-DSA", "Sign")] =
        [
            new FieldSpec("sk", "Signing key (sk)", FieldKind.InputFile, Required: true),
            new FieldSpec("file", "File to sign (leave blank if typing text below)", FieldKind.InputFile, Required: false),
            new FieldSpec("text", "...or type text to sign", FieldKind.TextMessage, Required: false),
            new FieldSpec("sig-out", "Signature out (blank = default)", FieldKind.OutputFile, Required: false),
        ],
        [("ML-DSA", "Verify")] =
        [
            new FieldSpec("pk", "Public key (pk)", FieldKind.InputFile, Required: true),
            new FieldSpec("file", "Signed file", FieldKind.InputFile, Required: true),
            new FieldSpec("sig", "Signature", FieldKind.InputFile, Required: true),
        ],
        [("ML-KEM", "Keygen")] =
        [
            new FieldSpec("out-dir", "Output folder (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFolder, Required: false),
        ],
        [("ML-KEM", "Encapsulate")] =
        [
            new FieldSpec("pk", "Public key (pk)", FieldKind.InputFile, Required: true),
            new FieldSpec("ct-out", "Ciphertext out (optional — defaults inside P-KAIDO/keys)", FieldKind.OutputFile, Required: false),
            new FieldSpec("ss-out", "Shared secret out (optional)", FieldKind.OutputFile, Required: false),
        ],
        [("ML-KEM", "Decapsulate")] =
        [
            new FieldSpec("sk", "Secret key (sk)", FieldKind.InputFile, Required: true),
            new FieldSpec("ct", "Ciphertext", FieldKind.InputFile, Required: true),
            new FieldSpec("ss-out", "Shared secret out (optional)", FieldKind.OutputFile, Required: false),
        ],
    };

    private readonly TextBox _cliPathBox;
    private readonly ComboBox _schemeBox;
    private readonly ComboBox _engineBox;
    private readonly ComboBox _variantBox;
    private readonly ComboBox _operationBox;
    private readonly TableLayoutPanel _fieldsPanel;
    private readonly DataGridView _grid;
    private readonly TextBox _detailBox;

    private readonly List<(TextBox Box, FieldSpec Spec)> _currentFields = [];
    private readonly BindingList<RunRow> _rows = [];
    private CustomDsaParamsResult? _customDsaParams;

    private sealed record RunRow(string Time, string Scheme, string Op, string Variant, string Engine, bool Ok, string Duration, string Summary, string RawJson);

    public MainForm()
    {
        Text = "P-KAIDO";
        Width = 1180;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            Padding = new Padding(10),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // cli path
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // scheme / engine / variant / operation
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // dynamic fields + run button
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // drop-a-file-to-inspect zone
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // results grid + JSON detail, side by side — takes all remaining space
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // footer
        Controls.Add(root);

        // --- CLI path row ---
        var cliRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, AutoSize = true };
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        cliRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        cliRow.Controls.Add(new Label { Text = "pqc-cli.exe:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 0, 0);
        _cliPathBox = new TextBox { Dock = DockStyle.Fill, Text = FindDefaultCliPath() ?? string.Empty };
        cliRow.Controls.Add(_cliPathBox, 1, 0);
        var browseCliButton = new Button { Text = "Browse...", AutoSize = true };
        browseCliButton.Click += (_, _) => BrowseForCli();
        cliRow.Controls.Add(browseCliButton, 2, 0);
        root.Controls.Add(cliRow, 0, 0);

        // --- Scheme / Engine / Variant / Operation, all as dropdowns in one row ---
        var optionsRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 8, AutoSize = true };
        optionsRow.Controls.Add(new Label { Text = "Scheme:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 0, 0);
        _schemeBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100, Margin = new Padding(3, 3, 16, 3) };
        _schemeBox.Items.AddRange(["ML-DSA", "ML-KEM"]);
        _schemeBox.SelectedIndexChanged += (_, _) => OnSchemeChanged();
        optionsRow.Controls.Add(_schemeBox, 1, 0);

        optionsRow.Controls.Add(new Label { Text = "Engine:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 2, 0);
        _engineBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110, Margin = new Padding(3, 3, 16, 3) };
        _engineBox.SelectedIndexChanged += (_, _) => OnEngineChanged();
        optionsRow.Controls.Add(_engineBox, 3, 0);

        optionsRow.Controls.Add(new Label { Text = "Variant:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 4, 0);
        _variantBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120, Margin = new Padding(3, 3, 16, 3) };
        optionsRow.Controls.Add(_variantBox, 5, 0);

        optionsRow.Controls.Add(new Label { Text = "Operation:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 6, 6, 0) }, 6, 0);
        _operationBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120, Margin = new Padding(3, 3, 0, 3) };
        _operationBox.SelectedIndexChanged += (_, _) => OnOperationChanged();
        optionsRow.Controls.Add(_operationBox, 7, 0);

        root.Controls.Add(optionsRow, 0, 1);

        // --- Dynamic file fields ---
        // Every field must always be fully visible — no internal scrollbar. Plain Panels with
        // Dock=Fill children don't report their content size upward for AutoSize rows to use,
        // so this whole area is built from AutoSize-aware TableLayoutPanels/FlowLayoutPanels.
        _fieldsPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(0, 6, 0, 6),
        };
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var runButton = new Button { Text = "Run", Width = 100, Height = 32, Anchor = AnchorStyles.Right };
        runButton.FlatStyle = FlatStyle.Flat;
        runButton.BackColor = AccentColor;
        runButton.ForeColor = TextColor;
        runButton.FlatAppearance.BorderColor = AccentHoverColor;
        runButton.FlatAppearance.MouseOverBackColor = AccentHoverColor;
        runButton.Click += (_, _) => RunClicked();
        var runRow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        runRow.Controls.Add(runButton);

        var fieldsGroup = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
        };
        fieldsGroup.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fieldsGroup.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        fieldsGroup.Controls.Add(_fieldsPanel, 0, 0);
        fieldsGroup.Controls.Add(runRow, 0, 1);
        root.Controls.Add(fieldsGroup, 0, 2);

        // --- Drop a file here to view its hex, no need to run it through an operation ---
        var inspectZone = new Label
        {
            Text = "Drop a file here to view its hex (or click to browse)",
            Dock = DockStyle.Fill,
            Height = 32,
            TextAlign = ContentAlignment.MiddleCenter,
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = PanelColor,
            ForeColor = SecondaryTextColor,
            Cursor = Cursors.Hand,
            AllowDrop = true,
            Margin = new Padding(0, 4, 0, 4),
        };
        inspectZone.DragEnter += (_, e) =>
        {
            e.Effect = e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy
                : DragDropEffects.None;
        };
        inspectZone.DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths)
            {
                foreach (var path in paths)
                {
                    InspectFile(path);
                }
            }
        };
        inspectZone.Click += (_, _) => BrowseAndInspectFile();
        root.Controls.Add(inspectZone, 0, 3);

        // --- Results grid ---
        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
        };
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time", DataPropertyName = nameof(RunRow.Time), Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Scheme", DataPropertyName = nameof(RunRow.Scheme), Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Op", DataPropertyName = nameof(RunRow.Op), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Variant", DataPropertyName = nameof(RunRow.Variant), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Engine", DataPropertyName = nameof(RunRow.Engine), Width = 80 });
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "OK", DataPropertyName = nameof(RunRow.Ok), Width = 40 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Duration", DataPropertyName = nameof(RunRow.Duration), Width = 80 });
        var summaryColumn = new DataGridViewTextBoxColumn { HeaderText = "Summary", DataPropertyName = nameof(RunRow.Summary), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill };
        _grid.Columns.Add(summaryColumn);

        _grid.BackgroundColor = PanelColor;
        _grid.GridColor = BorderColor;
        _grid.BorderStyle = BorderStyle.FixedSingle;
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = BgColor,
            ForeColor = TextColor,
            SelectionBackColor = BgColor,
            SelectionForeColor = TextColor,
        };
        _grid.DefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = PanelColor,
            ForeColor = TextColor,
            SelectionBackColor = AccentColor,
            SelectionForeColor = TextColor,
        };
        _grid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = InputBgColor };
        _grid.RowHeadersDefaultCellStyle.SelectionBackColor = BgColor;

        _grid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex != summaryColumn.Index || _grid.Rows[e.RowIndex].DataBoundItem is not RunRow row)
            {
                return;
            }

            e.CellStyle!.ForeColor = row.Ok ? GoldColor : ErrorColor;
        };

        _grid.DataSource = _rows;
        _grid.SelectionChanged += (_, _) => OnGridSelectionChanged();

        // --- Detail box ---
        _detailBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font(FontFamily.GenericMonospace, 9),
        };

        // --- Results row: grid on the left, JSON detail on the right, draggable splitter between them ---
        var resultsSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterWidth = 6,
        };
        resultsSplit.Panel1.Controls.Add(_grid);
        resultsSplit.Panel2.Controls.Add(_detailBox);
        root.Controls.Add(resultsSplit, 0, 4);
        // Panel min sizes and SplitterDistance can't be set reliably until the control has its
        // real, laid-out width (it's still the default 150x150 stub during construction).
        Load += (_, _) =>
        {
            resultsSplit.Panel1MinSize = 300;
            resultsSplit.Panel2MinSize = 200;
            resultsSplit.FixedPanel = FixedPanel.Panel2;
            resultsSplit.SplitterDistance = Math.Max(resultsSplit.Panel1MinSize, resultsSplit.Width - 320 - resultsSplit.SplitterWidth);
        };

        // --- Footer ---
        var footerLabel = new Label
        {
            Text = "post kuantum algoritma işlem deney ortamı",
            Dock = DockStyle.Fill,
            AutoSize = true,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = SecondaryTextColor,
            Padding = new Padding(0, 6, 0, 0),
        };
        root.Controls.Add(footerLabel, 0, 5);

        BackColor = BgColor;
        ForeColor = TextColor;
        ThemeTree(this);

        _schemeBox.SelectedIndex = 0;
    }

    private void OnSchemeChanged()
    {
        var scheme = (string)_schemeBox.SelectedItem!;

        _variantBox.Items.Clear();
        _variantBox.Items.AddRange(VariantsByScheme[scheme]);
        _variantBox.SelectedIndex = 0;
        _variantBox.Enabled = true;

        _engineBox.Items.Clear();
        _engineBox.Items.AddRange(EnginesByScheme[scheme]);
        _engineBox.SelectedIndex = 0;

        // Clearing Items resets SelectedIndex to -1, so setting it to 0 always changes it and
        // fires SelectedIndexChanged — that's what drives OnOperationChanged for this scheme.
        _operationBox.Items.Clear();
        _operationBox.Items.AddRange(OperationsByScheme[scheme]);
        _operationBox.SelectedIndex = 0;
    }

    private void OnEngineChanged()
    {
        if (GetSelectedEngine() != "custom")
        {
            _customDsaParams = null;
            _variantBox.Enabled = true;
            OnOperationChanged();
            return;
        }

        var result = CustomDsaParamsForm.ShowParamsDialog(this, _cliPathBox.Text);
        if (result is null)
        {
            // Don't leave a half-configured "custom" selection with no params behind it.
            _customDsaParams = null;
            _engineBox.SelectedIndex = 0;
            return;
        }

        _customDsaParams = result;
        _variantBox.Enabled = false;
        OnOperationChanged();
    }

    private string? GetSelectedVariant() => _variantBox.SelectedItem as string;

    private string? GetSelectedOperation() => _operationBox.SelectedItem as string;

    private string? GetSelectedEngine() => _engineBox.SelectedItem as string;

    private void OnOperationChanged()
    {
        _fieldsPanel.Controls.Clear();
        _fieldsPanel.RowStyles.Clear();
        _fieldsPanel.RowCount = 0;
        _currentFields.Clear();

        if (_schemeBox.SelectedItem is not string scheme || GetSelectedOperation() is not string op)
        {
            return;
        }

        // OnSchemeChanged rebuilds _engineBox before _operationBox, and the engine-changed
        // handler calls back into here — so this can run with `op` still holding the previous
        // scheme's operation name (e.g. "Encapsulate" while `scheme` already reads "ML-DSA").
        // _operationBox's own rebuild fires a second, consistent call right after; this one
        // just needs to not crash.
        if (!FieldsByOp.TryGetValue((scheme, op), out var specs))
        {
            return;
        }

        if (GetSelectedEngine() == "custom" && (op == "Sign" || op == "Verify"))
        {
            FieldSpec paramsField = new("params", "Custom params file (from keygen)", FieldKind.InputFile, Required: true);
            specs = [paramsField, .. specs];
        }

        for (int i = 0; i < specs.Length; i++)
        {
            var spec = specs[i];
            _fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _fieldsPanel.RowCount++;

            var label = new Label
            {
                Text = spec.Label + (spec.Required ? " *" : ""),
                AutoSize = true,
                Anchor = AnchorStyles.Left,
                Padding = new Padding(0, 6, 6, 0),
            };
            ThemeControl(label);
            _fieldsPanel.Controls.Add(label, 0, i);

            TextBox box;
            if (spec.Kind == FieldKind.TextMessage)
            {
                box = new TextBox
                {
                    Multiline = true,
                    Height = 70,
                    ScrollBars = ScrollBars.Vertical,
                    Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                };
            }
            else
            {
                box = new TextBox { Dock = DockStyle.Fill };
            }
            ThemeControl(box);
            _fieldsPanel.Controls.Add(box, 1, i);

            if (spec.Kind != FieldKind.TextMessage)
            {
                var browse = new Button { Text = "Browse...", AutoSize = true };
                var capturedSpec = spec;
                browse.Click += (_, _) => BrowseForField(box, capturedSpec);
                ThemeControl(browse);
                _fieldsPanel.Controls.Add(browse, 2, i);
            }

            _currentFields.Add((box, spec));
        }
    }

    private static void BrowseForField(TextBox box, FieldSpec spec)
    {
        switch (spec.Kind)
        {
            case FieldKind.OutputFolder:
                using (var dialog = new FolderBrowserDialog())
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.SelectedPath;
                    }
                }
                break;

            case FieldKind.OutputFile:
                using (var dialog = new SaveFileDialog { OverwritePrompt = false })
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.FileName;
                    }
                }
                break;

            case FieldKind.InputFile:
            default:
                using (var dialog = new OpenFileDialog())
                {
                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        box.Text = dialog.FileName;
                    }
                }
                break;
        }
    }

    private void BrowseForCli()
    {
        using var dialog = new OpenFileDialog { Filter = "pqc-cli|pqc-cli.exe|All files|*.*" };
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _cliPathBox.Text = dialog.FileName;
        }
    }

    private void RunClicked()
    {
        if (string.IsNullOrWhiteSpace(_cliPathBox.Text))
        {
            MessageBox.Show(this, "Set the path to pqc-cli.exe first.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_schemeBox.SelectedItem is not string scheme || GetSelectedOperation() is not string op || GetSelectedEngine() is not string engine)
        {
            return;
        }

        if (engine == "custom")
        {
            RunCustomDsa(op);
            return;
        }

        if (GetSelectedVariant() is not string variant)
        {
            return;
        }

        var schemeArg = scheme == "ML-DSA" ? "ml-dsa" : "ml-kem";
        var opArg = op.ToLowerInvariant();
        var args = new List<string> { schemeArg, opArg, "--variant", variant, "--engine", engine };

        if (op == "Keygen")
        {
            string? requestedFolder = null;
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.ArgName == "out-dir")
                {
                    requestedFolder = box.Text;
                }
            }

            string folder = ResolveKeygenFolder(requestedFolder, variant, engine);
            try
            {
                Directory.CreateDirectory(folder);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create '{folder}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            args.Add("--sk-out");
            args.Add(Path.Combine(folder, $"{variant}-sk.bin"));
            args.Add("--pk-out");
            args.Add(Path.Combine(folder, $"{variant}-pk.bin"));
        }
        else if (op == "Sign")
        {
            TextBox? skBox = null, fileBox = null, textBox = null, sigOutBox = null;
            foreach (var (box, spec) in _currentFields)
            {
                switch (spec.ArgName)
                {
                    case "sk": skBox = box; break;
                    case "file": fileBox = box; break;
                    case "text": textBox = box; break;
                    case "sig-out": sigOutBox = box; break;
                }
            }

            if (skBox is null || string.IsNullOrWhiteSpace(skBox.Text))
            {
                MessageBox.Show(this, "'Signing key (sk)' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool hasFile = fileBox is not null && !string.IsNullOrWhiteSpace(fileBox.Text);
            bool hasText = textBox is not null && !string.IsNullOrWhiteSpace(textBox.Text);

            if (hasFile == hasText)
            {
                MessageBox.Show(
                    this,
                    hasFile
                        ? "Provide either a file to sign or typed text — not both."
                        : "Nothing to sign. Pick a file, or type text in the box below.",
                    "P-KAIDO",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            args.Add("--sk");
            args.Add(skBox.Text);

            string fileToSign;
            if (hasFile)
            {
                fileToSign = fileBox!.Text;
            }
            else
            {
                try
                {
                    fileToSign = WriteTypedMessage(textBox!.Text, variant);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Couldn't save typed text:\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            args.Add("--file");
            args.Add(fileToSign);

            if (sigOutBox is not null && !string.IsNullOrWhiteSpace(sigOutBox.Text))
            {
                args.Add("--sig-out");
                args.Add(sigOutBox.Text);
            }
        }
        else if (op == "Encapsulate")
        {
            TextBox? pkBox = null, ctOutBox = null, ssOutBox = null;
            foreach (var (box, spec) in _currentFields)
            {
                switch (spec.ArgName)
                {
                    case "pk": pkBox = box; break;
                    case "ct-out": ctOutBox = box; break;
                    case "ss-out": ssOutBox = box; break;
                }
            }

            if (pkBox is null || string.IsNullOrWhiteSpace(pkBox.Text))
            {
                MessageBox.Show(this, "'Public key (pk)' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            args.Add("--pk");
            args.Add(pkBox.Text);

            string ctOutPath = ResolveCiphertextPath(ctOutBox?.Text, variant);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ctOutPath)!);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create output folder for '{ctOutPath}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            args.Add("--ct-out");
            args.Add(ctOutPath);

            if (ssOutBox is not null && !string.IsNullOrWhiteSpace(ssOutBox.Text))
            {
                args.Add("--ss-out");
                args.Add(ssOutBox.Text);
            }
        }
        else
        {
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.Required && string.IsNullOrWhiteSpace(box.Text))
                {
                    MessageBox.Show(this, $"'{spec.Label}' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            foreach (var (box, spec) in _currentFields)
            {
                if (!string.IsNullOrWhiteSpace(box.Text))
                {
                    args.Add("--" + spec.ArgName);
                    args.Add(box.Text);
                }
            }
        }

        RunCliAndRecord(args, scheme, op, variant, engine);
    }

    /// Shared by both the standard (rustcrypto/libcrux) and custom-engine run paths: launches
    /// pqc-cli, parses its JSON stdout, and appends a row to the results grid.
    private void RunCliAndRecord(List<string> args, string scheme, string op, string variantLabel, string engineLabel)
    {
        CliResult result;
        try
        {
            result = CliRunner.Run(_cliPathBox.Text, args);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Failed to launch pqc-cli:\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        string rawJson = result.StdOut.Length > 0 ? result.StdOut : result.StdErr;
        bool ok = false;
        string summary = rawJson;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            ok = root.TryGetProperty("ok", out var okProp) && okProp.GetBoolean();
            summary = Summarize(root, ok);
        }
        catch (JsonException)
        {
            summary = string.IsNullOrEmpty(rawJson) ? "(no output)" : rawJson;
        }

        string duration = FormatDuration(result.Elapsed);
        _rows.Insert(0, new RunRow(DateTime.Now.ToString("HH:mm:ss"), scheme, op, variantLabel, engineLabel, ok, duration, summary, rawJson));
        if (_grid.Rows.Count > 0)
        {
            _grid.ClearSelection();
            _grid.Rows[0].Selected = true;
        }
    }

    private void RunCustomDsa(string op)
    {
        if (_customDsaParams is not { } p)
        {
            MessageBox.Show(this, "Set custom ML-DSA parameters first.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (op == "Keygen")
        {
            string? requestedFolder = null;
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.ArgName == "out-dir")
                {
                    requestedFolder = box.Text;
                }
            }

            string folder = ResolveKeygenFolder(requestedFolder, "custom", "custom");
            try
            {
                Directory.CreateDirectory(folder);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Couldn't create '{folder}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var args = new List<string>
            {
                "ml-dsa", "keygen-custom",
                "--k", p.K.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--l", p.L.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--q", p.Q.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--gamma1", p.Gamma1.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--sk-out", Path.Combine(folder, "custom-sk.bin"),
                "--pk-out", Path.Combine(folder, "custom-pk.bin"),
                "--params-out", Path.Combine(folder, "custom-params.json"),
            };
            RunCliAndRecord(args, "ML-DSA", op, "custom", "custom");
            return;
        }

        // Sign / Verify: reuse the same dynamic fields as the standard engine (sk/file/text/
        // sig-out or pk/file/sig), plus the "params" field prepended in OnOperationChanged.
        foreach (var (box, spec) in _currentFields)
        {
            if (spec.Required && string.IsNullOrWhiteSpace(box.Text))
            {
                MessageBox.Show(this, $"'{spec.Label}' is required.", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }

        if (op == "Sign")
        {
            TextBox? fileBox = null, textBox = null;
            foreach (var (box, spec) in _currentFields)
            {
                if (spec.ArgName == "file") fileBox = box;
                if (spec.ArgName == "text") textBox = box;
            }

            bool hasFile = fileBox is not null && !string.IsNullOrWhiteSpace(fileBox.Text);
            bool hasText = textBox is not null && !string.IsNullOrWhiteSpace(textBox.Text);
            if (hasFile == hasText)
            {
                MessageBox.Show(
                    this,
                    hasFile ? "Provide either a file to sign or typed text — not both." : "Nothing to sign. Pick a file, or type text in the box below.",
                    "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (hasText)
            {
                try
                {
                    fileBox!.Text = WriteTypedMessage(textBox!.Text, "custom");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, $"Couldn't save typed text:\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
        }

        var signVerifyArgs = new List<string> { "ml-dsa", op == "Sign" ? "sign-custom" : "verify-custom" };
        foreach (var (box, spec) in _currentFields)
        {
            if (!string.IsNullOrWhiteSpace(box.Text))
            {
                signVerifyArgs.Add("--" + spec.ArgName);
                signVerifyArgs.Add(box.Text);
            }
        }

        RunCliAndRecord(signVerifyArgs, "ML-DSA", op, "custom", "custom");
    }

    private static string Summarize(JsonElement root, bool ok)
    {
        if (!ok)
        {
            return root.TryGetProperty("error", out var err) ? err.GetString() ?? "error" : "error";
        }

        if (root.TryGetProperty("valid", out var valid))
        {
            return valid.GetBoolean() ? "signature valid" : "signature INVALID";
        }

        if (root.TryGetProperty("shared_secret_hex", out var ss))
        {
            return "shared secret " + ss.GetString();
        }

        if (root.TryGetProperty("sk_path", out var skPath) && root.TryGetProperty("pk_path", out var pkPath))
        {
            return $"keypair written to {skPath.GetString()} / {pkPath.GetString()}";
        }

        if (root.TryGetProperty("signature_path", out var sigPath))
        {
            string signedFile = root.TryGetProperty("file", out var f) ? f.GetString() ?? "?" : "?";
            return $"signed '{signedFile}', signature at {sigPath.GetString()}";
        }

        return "ok";
    }

    private void BrowseAndInspectFile()
    {
        using var dialog = new OpenFileDialog { Filter = "All files|*.*", Multiselect = true };
        if (dialog.ShowDialog() == DialogResult.OK)
        {
            foreach (var path in dialog.FileNames)
            {
                InspectFile(path);
            }
        }
    }

    private void InspectFile(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Couldn't read '{path}':\n{ex.Message}", "P-KAIDO", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var json = JsonSerializer.Serialize(new
        {
            ok = true,
            op = "inspect",
            file = path,
            bytes = bytes.Length,
            hex = Convert.ToHexString(bytes).ToLowerInvariant(),
        });

        var row = new RunRow(
            DateTime.Now.ToString("HH:mm:ss"),
            "-",
            "Inspect",
            "-",
            "-",
            true,
            "-",
            $"{Path.GetFileName(path)} ({bytes.Length} bytes)",
            json);

        _rows.Insert(0, row);
        if (_grid.Rows.Count > 0)
        {
            _grid.ClearSelection();
            _grid.Rows[0].Selected = true;
        }
    }

    private void OnGridSelectionChanged()
    {
        if (_grid.SelectedRows.Count == 0 || _grid.SelectedRows[0].DataBoundItem is not RunRow row)
        {
            _detailBox.Text = string.Empty;
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(row.RawJson);
            _detailBox.Text = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException)
        {
            _detailBox.Text = row.RawJson;
        }
    }

    private static string FormatDuration(TimeSpan elapsed) =>
        elapsed.TotalSeconds.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture) + " s";

    private static string ResolveKeygenFolder(string? requestedFolder, string variant, string engine)
    {
        if (!string.IsNullOrWhiteSpace(requestedFolder))
        {
            return requestedFolder;
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(FindRepoRoot(), "keys", $"{stamp}_{variant}_{engine}");
    }

    private static string ResolveCiphertextPath(string? requestedPath, string variant)
    {
        if (!string.IsNullOrWhiteSpace(requestedPath))
        {
            return requestedPath;
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        return Path.Combine(FindRepoRoot(), "keys", $"{stamp}_{variant}-ct.bin");
    }

    private static string WriteTypedMessage(string text, string variant)
    {
        var folder = Path.Combine(FindRepoRoot(), "messages");
        Directory.CreateDirectory(folder);

        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var path = Path.Combine(folder, $"{stamp}_{variant}.txt");
        File.WriteAllText(path, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "engines")) && Directory.Exists(Path.Combine(dir.FullName, "ui")))
            {
                return dir.FullName;
            }
        }

        return AppContext.BaseDirectory;
    }

    // Applies the palette to one control based on its runtime type. Called both for the static
    // control tree (via ThemeTree) and at each dynamic control's creation site (scheme/operation
    // change rebuilds radio buttons and fields at runtime, so a one-time tree walk isn't enough).
    internal static void ThemeControl(Control control)
    {
        switch (control)
        {
            case Button button:
                button.FlatStyle = FlatStyle.Flat;
                button.BackColor = PanelColor;
                button.ForeColor = TextColor;
                button.FlatAppearance.BorderColor = BorderColor;
                button.FlatAppearance.MouseOverBackColor = BorderColor;
                break;
            case TextBox textBox:
                textBox.BackColor = InputBgColor;
                textBox.ForeColor = TextColor;
                textBox.BorderStyle = BorderStyle.FixedSingle;
                break;
            case ComboBox comboBox:
                comboBox.FlatStyle = FlatStyle.Flat;
                comboBox.BackColor = InputBgColor;
                comboBox.ForeColor = TextColor;
                break;
            case RadioButton radioButton:
                radioButton.ForeColor = TextColor;
                radioButton.BackColor = Color.Transparent;
                break;
            case Label label:
                label.ForeColor = TextColor;
                break;
            case DataGridView:
                break; // themed separately in the constructor — needs header/cell style, not just colors
            default:
                control.BackColor = BgColor;
                control.ForeColor = TextColor;
                break;
        }
    }

    internal static void ThemeTree(Control root)
    {
        foreach (Control child in root.Controls)
        {
            ThemeControl(child);
            if (child.HasChildren)
            {
                ThemeTree(child);
            }
        }
    }

    private static string? FindDefaultCliPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            foreach (var config in new[] { "debug", "release" })
            {
                var candidate = Path.Combine(dir.FullName, "engines", "target", config, "pqc-cli.exe");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }
}
