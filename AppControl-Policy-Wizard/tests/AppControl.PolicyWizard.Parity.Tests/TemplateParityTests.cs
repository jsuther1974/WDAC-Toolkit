using System.Xml.Linq;

namespace AppControl.PolicyWizard.Parity.Tests;

public sealed class TemplateParityTests
{
    [Theory]
    [InlineData("SignedReputable.xml")]
    [InlineData("DefaultWindows_Audit.xml")]
    public void SuccessorTemplateMatchesLegacyTemplate(string fileName)
    {
        XDocument legacy = XDocument.Load(
            Path.Combine(AppContext.BaseDirectory, "LegacyTemplates", fileName));
        XDocument successor = XDocument.Load(
            Path.Combine(AppContext.BaseDirectory, "SuccessorTemplates", fileName));

        Assert.True(
            XNode.DeepEquals(
                Normalize(legacy.Root!),
                Normalize(successor.Root!)),
            $"{fileName} has drifted from the legacy source template.");
    }

    private static XElement Normalize(XElement element)
    {
        return new XElement(
            element.Name,
            element.Attributes()
                .OrderBy(attribute => attribute.Name.ToString())
                .Select(attribute => new XAttribute(attribute)),
            NormalizeNodes(element));
    }

    private static IEnumerable<object> NormalizeNodes(XElement element)
    {
        foreach (XNode node in element.Nodes())
        {
            switch (node)
            {
                case XElement child:
                    yield return Normalize(child);
                    break;
                case XText text when !string.IsNullOrWhiteSpace(text.Value):
                    yield return new XText(text.Value);
                    break;
            }
        }
    }
}
