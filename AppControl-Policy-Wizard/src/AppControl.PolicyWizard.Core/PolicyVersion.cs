namespace AppControl.PolicyWizard.Core;

public static class PolicyVersion
{
    public static string Increment(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new InvalidDataException("The selected policy does not specify a VersionEx value.");
        }

        string[] fields = version.Split('.');
        if (fields.Length != 4)
        {
            throw new InvalidDataException(
                $"The policy version '{version}' must contain four numeric fields.");
        }

        var versionFields = new int[fields.Length];
        for (int index = 0; index < fields.Length; index++)
        {
            if (!int.TryParse(fields[index], out int value)
                || value < 0
                || value > ushort.MaxValue)
            {
                throw new InvalidDataException(
                    $"The policy version '{version}' contains an invalid UInt16 field.");
            }

            versionFields[index] = value;
        }

        int fieldIndex = versionFields.Length - 1;
        while (fieldIndex >= 0)
        {
            versionFields[fieldIndex]++;
            if (versionFields[fieldIndex] >= ushort.MaxValue)
            {
                versionFields[fieldIndex] = 0;
                fieldIndex--;
                continue;
            }

            break;
        }

        return string.Join('.', versionFields);
    }
}
