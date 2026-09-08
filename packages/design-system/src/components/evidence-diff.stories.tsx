import type { Meta, StoryObj } from "@storybook/react";
import { EvidenceDiff } from "./evidence-diff";

const meta: Meta<typeof EvidenceDiff> = {
  component: EvidenceDiff,
  title: "Redsim/EvidenceDiff",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof EvidenceDiff>;

const SAMPLE = `--- a/routes/login.js
+++ b/routes/login.js
@@ -1,5 +1,5 @@
 module.exports = function login () {
   return (req, res, next) => {
-    models.sequelize.query(\`SELECT * FROM Users WHERE email = '\${req.body.email}'\`)
+    models.sequelize.query('SELECT * FROM Users WHERE email = ?', { replacements: [req.body.email] })
   }
 }`;

export const SqliFix: Story = { args: { diff: SAMPLE } };
